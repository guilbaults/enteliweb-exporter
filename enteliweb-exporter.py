import requests
import json
import sys
import re
import base64
import configparser
import logging
import argparse
import http.server
import time
import os
import threading
from bs4 import BeautifulSoup
from urllib.parse import quote, urlparse, parse_qs


class EnteliwebExporter:
    def __init__(self, host, verify, discovery_ttl=3600):
        self.host = host
        self.verify = verify
        self.discovery_ttl = discovery_ttl
        self.lock = threading.RLock()
        self._point_cache = {}
        self._in_discovery = set()

        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
        self.session = requests.Session()
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def update_csrf_token(self):
        r = self.session.get("{}/enteliweb/".format(self.host), verify=self.verify, timeout=10)
        match = re.search(r'_token\s+= \"(.*)\";', r.text)
        if not match:
            logging.error("Could not extract CSRF token from Enteliweb root page")
            sys.exit(1)
        self.csrf_token = match.group(1)

    def login(self, username, password):
        with self.lock:
            self.update_csrf_token()

            r = self.session.post("{}/enteliweb/index/verify".format(self.host),
                data={
                    "userName": base64.b64encode(username.encode('ascii')),
                    "password": base64.b64encode(password.encode('ascii')),
                    "_csrfToken": self.csrf_token
                },
                verify=self.verify,
                timeout=10
            )
            if r.json()['success'] is not True:
                logging.error("Login failed")
                sys.exit(1)
            else:
                logging.info("Login successful")
            self.username = username
            self.password = password

            self.update_csrf_token()

    def _resolve_device_ref(self, controller_ref):
        r = self.session.get("{}/enteliweb/wsds/getdevicelist?ObjRef=%2F%2F*%2F*.DEV*&searchStr=".format(self.host),
            verify=self.verify, timeout=10)
        data = json.loads(r.text)
        for key in data['deviceList']:
            for ctrl in data['deviceList'][key]:
                if ctrl['Ref'].startswith(controller_ref.rstrip('/') + '.'):
                    return ctrl['Ref']
        logging.error(f"No device ref found for controller: {controller_ref}")
        sys.exit(1)

    def discover_points(self, controller_ref):
        start = time.time()
        device_ref = self._resolve_device_ref(controller_ref)
        r = self.session.post("{}/enteliweb/wsdevice/objectlist".format(self.host),
            data={
                "ObjRef": '["{}"]'.format(device_ref),
                "_csrfToken": self.csrf_token,
                "query": "",
                "sort": "ObjectInstance ASC"
            },
            verify=self.verify,
            timeout=60
        )
        if r.status_code == 401:
            with self.lock:
                logging.info("Login expired during discovery, logging in again")
                self.login(self.username, self.password)
                r = self.session.post("{}/enteliweb/wsdevice/objectlist".format(self.host),
                    data={
                        "ObjRef": '["{}"]'.format(device_ref),
                        "_csrfToken": self.csrf_token,
                        "query": "",
                        "sort": "ObjectInstance ASC"
                    },
                    verify=self.verify,
                    timeout=60
                )

        objects = json.loads(r.text)['objects']
        points = []
        for obj in objects:
            if re.search(r'\.(AI|AO|AV|BI|BO|CO)\d+', obj['FullRef'], re.IGNORECASE):
                points.append({
                    'full_ref': obj['FullRef'],
                    'name': obj.get('Name', ''),
                })
        elapsed = time.time() - start
        logging.info(f"Discovered {len(points)} points on {controller_ref} in {elapsed:.1f}s")
        return points

    def _get_or_discover(self, controller_ref):
        while True:
            with self.lock:
                now = time.time()
                cached = self._point_cache.get(controller_ref)
                if cached and (now - cached['timestamp']) < self.discovery_ttl:
                    return cached['points']
                if controller_ref in self._in_discovery:
                    waiting = True
                else:
                    self._in_discovery.add(controller_ref)
                    waiting = False
            if waiting:
                time.sleep(0.5)
                continue  # another thread is discovering, wait and retry
            points = self.discover_points(controller_ref)
            with self.lock:
                self._point_cache[controller_ref] = {'points': points, 'timestamp': time.time()}
                self._in_discovery.discard(controller_ref)
            return points


    def _fetch_values(self, refs):
        refs_str = '.Present_Value,'.join(refs) + '.Present_Value'
        data = {
            "input": refs_str,
            "_csrfToken": self.csrf_token,
        }
        r = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
            data=data,
            verify=self.verify,
            timeout=60
        )
        if r.status_code == 401:
            with self.lock:
                logging.info("Login expired, logging in again")
                self.login(self.username, self.password)
                r = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
                    data=data,
                    verify=self.verify,
                    timeout=60
                )
                if r.status_code == 401:
                    logging.error("Login failed again")
                    sys.exit(1)

        return self._parse_values(r.text, refs)

    @staticmethod
    def _parse_values(response_text, refs):
        if 'getcaptch' in response_text:
            logging.error("Got a captcha, lets die and retry")
            sys.exit(1)
        returned_values = response_text.lstrip('[').rstrip(']').split(',')[:-3]
        values = []
        for value in returned_values:
            try:
                v = value.strip('"')
                if v == 'inactive':
                    values.append(float(-1))
                elif v == 'active':
                    values.append(float(1))
                else:
                    values.append(float(v))
            except ValueError:
                values.append(None)
        return list(zip(refs, values))

    def collect_controller(self, controller_ref):
        lines = []
        metric_name = 'enteliweb_value'
        lines.append(f'# HELP {metric_name} Current value')
        lines.append(f'# TYPE {metric_name} gauge')

        points = self._get_or_discover(controller_ref)
        refs = [p['full_ref'] for p in points]

        if not refs:
            return '\n'.join(lines)

        values = self._fetch_values(refs)

        if all(val is None for _, val in values):
            logging.error("Controller %s appears to be offline — all points returned invalid values", controller_ref)
            return '\n'.join(lines)

        point_map = {p['full_ref']: p for p in points}
        for ref, val in sorted(values, key=lambda x: x[0]):
            if val is None:
                logging.error("Could not convert value of sensor %s", ref)
                continue
            info = point_map.get(ref, {})
            label = info.get('name', '')
            lines.append(f'{metric_name}{{bacnet_id="{ref}", label="{label}"}} {val}')

        return '\n'.join(lines)

    def get_controller_program(self, obj_ref):
        url = "{}/enteliweb/object/display?ObjRef={}".format(self.host, quote(obj_ref, safe=''))
        r = self.session.get(url, verify=self.verify, timeout=30)
        soup = BeautifulSoup(r.text, 'html.parser')
        editor_div = soup.find('div', id='div_Program_Editor')
        if not editor_div:
            return None
        textarea = editor_div.find('textarea', id='Editor')
        if not textarea:
            return None
        raw = textarea.get_text()
        return json.loads(raw)[0]

    def save_controller_programs(self, controller_ref):
        device_ref = self._resolve_device_ref(controller_ref)
        r = self.session.post("{}/enteliweb/wsdevice/objectlist".format(self.host),
            data={
                "ObjRef": '["{}"]'.format(device_ref),
                "_csrfToken": self.csrf_token,
                "query": "",
                "sort": "ObjectInstance ASC"
            },
            verify=self.verify,
            timeout=60
        )
        objects = json.loads(r.text)['objects']

        program_dir = 'controller_programs'
        os.makedirs(program_dir, exist_ok=True)
        count = 0
        for obj in objects:
            if re.search(r'\.PG\d+$', obj['FullRef'], re.IGNORECASE):
                program_code = self.get_controller_program(obj['FullRef'])
                if program_code is not None:
                    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', obj['FullRef'])
                    filepath = os.path.join(program_dir, safe_name + '.txt')
                    with open(filepath, 'w') as f:
                        f.write(program_code)
                    logging.info(f"Saved program for {obj['FullRef']} to {filepath}")
                    count += 1
        logging.info(f"Saved {count} programs for {controller_ref} to {program_dir}/")


class MetricsHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith('/metrics'):
            logging.debug(f"GET {self.path}")
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            controller = params.get('controller', [None])[0]
            if not controller:
                self.send_response(400)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                try:
                    self.wfile.write(b'Missing ?controller=//site/XXXXX parameter\n')
                except BrokenPipeError:
                    logging.error("Broken pipe while writing error response to %s", self.client_address)
                return
            controller = controller.split(':')[0]
            logging.debug(f"Controller: {controller}")

            body = eweb.collect_controller(controller).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                logging.error("Broken pipe while writing metrics for controller=%s to %s", controller, self.client_address)
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            try:
                self.wfile.write(b'OK\n')
            except BrokenPipeError:
                logging.error("Broken pipe while writing health response to %s", self.client_address)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enteliweb exporter')
    parser.add_argument('config')
    parser.add_argument('--log-level', default='INFO')
    parser.add_argument('--get-programs', action='store', help='Fetch all programs from a controller and save to controller_programs/. Pass the controller ref, e.g. //site/10000')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)

    logging.basicConfig(level=args.log_level, format='%(asctime)s %(levelname)s %(message)s')

    if config['enteliweb']['insecure'] == 'true':
        import urllib3
        urllib3.disable_warnings()
        verify = False
    else:
        verify = True

    discovery_ttl = int(config['exporter'].get('discovery_ttl', 3600))
    eweb = EnteliwebExporter(config['enteliweb']['host'], verify, discovery_ttl)
    eweb.login(config['enteliweb']['username'], config['enteliweb']['password'])

    if args.get_programs:
        eweb.save_controller_programs(args.get_programs)
        sys.exit(0)

    port = int(config['exporter']['port'])
    httpd = http.server.ThreadingHTTPServer(('', port), MetricsHandler)
    logging.info(f'Serving metrics on port {port}')
    httpd.serve_forever()
