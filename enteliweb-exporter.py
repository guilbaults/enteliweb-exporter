import requests
import json
import random
import sys
import re
import base64
import configparser
import logging
import argparse
import http.server
import socketserver
import time
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import quote, urlparse, parse_qs


class EnteliwebExporter:
    def __init__(self, host, verify, discovery_ttl=3600):
        self.host = host
        self.verify = verify
        self.discovery_ttl = discovery_ttl  # base TTL; actual expiry is randomised ±50%
        self.lock = threading.RLock()
        self._point_cache = {}
        self._in_discovery = set()

        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
        self.session = requests.Session()
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def update_csrf_token(self):
        r = self.session.get("{}/enteliweb/".format(self.host), verify=self.verify, timeout=60)
        match = re.search(r'_token\s+= \"(.*)\";', r.text)
        if not match:
            logging.error(
                "Exiting: could not extract CSRF token from %s — "
                "response status %d, first 500 chars: %s",
                self.host, r.status_code, r.text[:500])
            sys.exit(1)
        self.csrf_token = match.group(1)

    def login(self, username, password):
        with self.lock:
            self.update_csrf_token()

            r = self.session.post(
                "{}/enteliweb/index/verify".format(self.host),
                data={
                    "userName": base64.b64encode(username.encode('ascii')),
                    "password": base64.b64encode(password.encode('ascii')),
                    "_csrfToken": self.csrf_token,
                },
                verify=self.verify,
                timeout=60,
            )
            try:
                login_ok = r.json()['success']
            except json.JSONDecodeError:
                self._save_response_and_exit(r)
            if login_ok is not True:
                logging.error(
                    "Exiting: login to %s failed — status %d, response: %s",
                    self.host, r.status_code, r.text[:500])
                sys.exit(1)
            else:
                logging.info("Login successful")
            self.username = username
            self.password = password

            self.update_csrf_token()

    @staticmethod
    def _save_response_and_exit(response):
        with open("debug_response.html", 'w') as f:
            f.write(response.text)
        logging.error(
            "Exiting: JSON parse failed for %s (status %d) — "
            "raw response saved to debug_response.html",
            response.url, response.status_code)
        sys.exit(1)

    def _resolve_device_ref(self, controller_ref):
        r = self.session.get(
            "{}/enteliweb/wsds/getdevicelist?ObjRef=%2F%2F*%2F*.DEV*&searchStr="
            .format(self.host),
            verify=self.verify,
            timeout=60,
        )
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            self._save_response_and_exit(r)
        for key in data['deviceList']:
            for ctrl in data['deviceList'][key]:
                if ctrl['Ref'].startswith(controller_ref.rstrip('/') + '.'):
                    return ctrl['Ref']
        logging.error(
            "Exiting: no device ref found for controller %s — "
            "got %d devices from %s",
            controller_ref,
            sum(len(v) for v in data['deviceList'].values()),
            self.host)
        sys.exit(1)

    def discover_points(self, controller_ref):
        start = time.time()
        device_ref = self._resolve_device_ref(controller_ref)
        r = self.session.post(
            "{}/enteliweb/wsdevice/objectlist".format(self.host),
            data={
                "ObjRef": '["{}"]'.format(device_ref),
                "_csrfToken": self.csrf_token,
                "query": "",
                "sort": "ObjectInstance ASC",
            },
            verify=self.verify,
            timeout=60,
        )
        if r.status_code == 401:
            logging.info("Login expired during discovery, logging in again")
            with self.lock:
                self.login(self.username, self.password)
            device_ref = self._resolve_device_ref(controller_ref)
            r = self.session.post(
                "{}/enteliweb/wsdevice/objectlist".format(self.host),
                data={
                    "ObjRef": '["{}"]'.format(device_ref),
                    "_csrfToken": self.csrf_token,
                    "query": "",
                    "sort": "ObjectInstance ASC",
                },
                verify=self.verify,
                timeout=60,
            )

        try:
            objects = json.loads(r.text)['objects']
        except json.JSONDecodeError:
            self._save_response_and_exit(r)
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
        wait_start = time.time()
        wait_timeout = 120  # max seconds to wait for another thread's discovery
        while True:
            with self.lock:
                now = time.time()
                cached = self._point_cache.get(controller_ref)
                if cached and (now - cached['timestamp']) < cached.get('ttl', self.discovery_ttl):
                    return cached['points']
                if controller_ref in self._in_discovery:
                    # If we've waited too long, the discovering thread likely
                    # crashed.  Nuke the stale entry and retry.
                    if now - wait_start > wait_timeout:
                        logging.warning(
                            "Discovery for %s stalled for %ds — resetting and retrying",
                            controller_ref, int(now - wait_start))
                        self._in_discovery.discard(controller_ref)
                        continue
                    waiting = True
                else:
                    self._in_discovery.add(controller_ref)
                    waiting = False
            if waiting:
                time.sleep(0.5)
                continue  # another thread is discovering, wait and retry
            try:
                points = self.discover_points(controller_ref)
            except Exception:
                with self.lock:
                    self._in_discovery.discard(controller_ref)
                raise
            with self.lock:
                ttl = random.randint(int(self.discovery_ttl * 0.5),
                                     int(self.discovery_ttl * 1.5))
                self._point_cache[controller_ref] = {
                    'points': points, 'timestamp': time.time(), 'ttl': ttl
                }
                self._in_discovery.discard(controller_ref)
            return points

    def _fetch_values(self, refs):
        refs_str = '.Present_Value,'.join(refs) + '.Present_Value'
        data = {
            "input": refs_str,
            "_csrfToken": self.csrf_token,
        }
        r = self.session.post(
            "{}/enteliweb/wsbacv3/getvalue".format(self.host),
            data=data,
            verify=self.verify,
            timeout=60,
        )
        if r.status_code == 401:
            logging.info("Login expired during value fetch, logging in again")
            with self.lock:
                self.login(self.username, self.password)
            data["_csrfToken"] = self.csrf_token
            r = self.session.post(
                "{}/enteliweb/wsbacv3/getvalue".format(self.host),
                data=data,
                verify=self.verify,
                timeout=60,
            )
            if r.status_code == 401:
                logging.error(
                    "Exiting: value fetch still 401 after re-login — "
                    "status %d, response: %s",
                    r.status_code, r.text[:500])
                sys.exit(1)

        return self._parse_values(r.text, refs)

    @staticmethod
    def _parse_values(response_text, refs):
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

    def collect_controller(self, controller_ref, handler=None):
        lines = []
        metric_name = 'enteliweb_value'
        lines.append(f'# HELP {metric_name} Current value')
        lines.append(f'# TYPE {metric_name} gauge')

        points = self._get_or_discover(controller_ref)

        if handler and handler.wfile.closed:
            return  # client disconnected during discovery, save remaining work

        refs = [p['full_ref'] for p in points]

        if not refs:
            return '\n'.join(lines)

        values = self._fetch_values(refs)

        if all(val is None for _, val in values):
            logging.debug("Controller %s appears to be offline — all points returned invalid values", controller_ref)
            msg = 'Controller {} appears to be offline — all points returned invalid values\n'.format(controller_ref)
            return (503, msg)

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
        r = self.session.post(
            "{}/enteliweb/wsdevice/objectlist".format(self.host),
            data={
                "ObjRef": '["{}"]'.format(device_ref),
                "_csrfToken": self.csrf_token,
                "query": "",
                "sort": "ObjectInstance ASC",
            },
            verify=self.verify,
            timeout=60,
        )
        try:
            objects = json.loads(r.text)['objects']
        except json.JSONDecodeError:
            self._save_response_and_exit(r)

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

            body = eweb.collect_controller(controller, self)
            if body is None:
                return  # client disconnected during discovery

            if isinstance(body, tuple):
                status_code, error_body = body
                body = error_body.encode('utf-8')
                self.send_response(status_code)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    logging.error("Broken pipe while writing error response to %s", self.client_address)
                return

            body = body.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                logging.error(
                    "Broken pipe while writing metrics for controller=%s to %s",
                    controller, self.client_address)
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


class BoundedThreadPoolHTTPServer(socketserver.TCPServer):
    """HTTP server that processes requests in a fixed-size thread pool.

    Unlike ThreadingHTTPServer (which spawns an unbounded new thread per
    request), this server reuses a bounded pool of worker threads.  If all
    workers are busy, incoming connections queue up instead of exhausting
    OS threads.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, max_workers=10):
        super().__init__(server_address, RequestHandlerClass)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def process_request(self, request, client_address):
        self.executor.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)

    def server_close(self):
        self.executor.shutdown(wait=True)
        super().server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enteliweb exporter')
    parser.add_argument('config')
    parser.add_argument('--log-level', default='INFO')
    parser.add_argument(
        '--get-programs', action='store',
        help='Fetch all programs from a controller and save to '
        'controller_programs/. Pass the controller ref, e.g. //site/10000')
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
    max_workers = int(config['exporter'].get('max_workers', 50))
    httpd = BoundedThreadPoolHTTPServer(('', port), MetricsHandler, max_workers=max_workers)
    logging.info(f'Serving metrics on port {port} (max {max_workers} concurrent workers)')
    httpd.serve_forever()
