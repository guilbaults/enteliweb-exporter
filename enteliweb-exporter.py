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
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import quote

class EnteliwebExporter:
    def __init__(self, host, devices, verify, max_workers=5):
        self.host = host
        self.devices = devices
        self.verify = verify
        self.max_workers = max_workers
        self.lock = threading.Lock()

        pool_size = max_workers * 2
        adapter = requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        self.session = requests.Session()
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def update_csrf_token(self):
        s = self.session.get("{}/enteliweb/".format(self.host), verify=self.verify, timeout=10)
        # grab the csrf token from the html
        self.csrf_token = re.search(r'_token\s+= \"(.*)\";', s.text).group(1)

    def login(self, username, password):
        self.update_csrf_token()

        s = self.session.post("{}/enteliweb/index/verify".format(self.host),
            # Enteliweb is expecting a base64 encoded string
            data={
                "userName": base64.b64encode(username.encode('ascii')),
                "password": base64.b64encode(password.encode('ascii')),
                "_csrfToken": self.csrf_token
            },
            verify=self.verify,
            timeout=10
        )
        if s.json()['success'] is not True:
            logging.error("Login failed")
            sys.exit(1)
        else:
            logging.info("Login successful")
            self.username = username
            self.password = password

        self.update_csrf_token()

    @staticmethod
    def _extract_controller(bacnet_id):
        # Extract controller path from BACnet ID: //site/10000.AO001 -> //site/10000
        return bacnet_id.rsplit('.', 1)[0]

    def _parse_values(self, response_text, device_ids):
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
                try:
                    logging.error("Could not convert value of sensor {} to float ({})".format(device_ids[len(values)-1], value))
                except IndexError:
                    logging.error("Sensor index out of range")
        return list(zip(device_ids, values))

    def _fetch_controller_values(self, device_ids):
        start_time = time.time()
        device_ids_str = '.Present_Value,'.join(map(lambda x: x[0], device_ids))
        device_ids_str += '.Present_Value'
        data = {
            "input": device_ids_str,
            "_csrfToken": self.csrf_token,
        }
        s = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
            data=data,
            verify=self.verify,
            timeout=60
        )
        if s.status_code == 401:
            with self.lock:
                logging.info("Login expired, logging in again")
                self.login(self.username, self.password)
                s = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
                    data=data,
                    verify=self.verify,
                    timeout=60
                )
                if s.status_code == 401:
                    logging.error("Login failed again")
                    sys.exit(1)
        elapsed = time.time() - start_time
        return self._parse_values(s.text, device_ids), elapsed

    def get_values(self, device_ids):
        # Group devices by controller
        controllers = {}
        for dev in device_ids:
            ctrl = self._extract_controller(dev[0])
            if ctrl not in controllers:
                controllers[ctrl] = []
            controllers[ctrl].append(dev)

        logging.info(f"Fetching values for {len(controllers)} controllers ({len(device_ids)} devices)")

        all_values = []
        controller_timings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_controller = {
                executor.submit(self._fetch_controller_values, devs): ctrl
                for ctrl, devs in controllers.items()
            }
            for future in concurrent.futures.as_completed(future_to_controller):
                ctrl = future_to_controller[future]
                try:
                    result, elapsed = future.result()
                    all_values.extend(result)
                    controller_timings.append((ctrl, elapsed))
                except Exception as e:
                    logging.error(f"Error fetching values for controller {ctrl}: {e}")

        return all_values, controller_timings

    def get_all_points(self, controller_regex):
        # This will go through all the controllers and print the Ref and Name of each point
        s = self.session.get("{}/enteliweb/wsds/getdevicelist?ObjRef=%2F%2F*%2F*.DEV*&searchStr=".format(self.host), verify=self.verify, timeout=10)
        data = json.loads(s.text)
        lines = []
        for key in data['deviceList']:
            for controller in data['deviceList'][key]:
                if not re.search(controller_regex, controller['Ref']):
                    # If the controller doesn't match the regex, we skip it
                    continue
                try:
                    s = self.session.post("{}/enteliweb/wsdevice/objectlist".format(self.host),
                        data = {
                            "ObjRef": '["{}"]'.format(controller['Ref']),
                            "_csrfToken": self.csrf_token,
                            "query": "",
                            "sort": "ObjectInstance ASC"
                        },
                        verify=self.verify,
                        timeout=60
                    )
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error fetching points for controller {controller['Ref']}: {e}")
                    continue
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON for controller {controller['Ref']}: {e}")
                    continue
                objects = json.loads(s.text)['objects']
                for obj in objects:
                    # We only keep about AV, AI, AO, BI, BO, CO points
                    if re.search(r'\.(AI|AO|AV|BI|BO|CO)\d+', obj['FullRef'], re.IGNORECASE):
                        lines.append(f'{obj["FullRef"]} = {obj["Name"]}')
                time.sleep(1) # Sleep a bit to avoid overwhelming the server
        with open(config['enteliweb']['devices_file'], 'w') as f:
            f.write('\n'.join(lines) + '\n')
        logging.info(f"Saved {len(lines)} points to {config['enteliweb']['devices_file']}")

    def get_controller_program(self, obj_ref):
        url = "{}/enteliweb/object/display?ObjRef={}".format(self.host, quote(obj_ref, safe=''))
        s = self.session.get(url, verify=self.verify, timeout=30)
        soup = BeautifulSoup(s.text, 'html.parser')
        editor_div = soup.find('div', id='div_Program_Editor')
        if not editor_div:
            return None
        textarea = editor_div.find('textarea', id='Editor')
        if not textarea:
            return None
        raw = textarea.get_text()
        return json.loads(raw)[0]

    def save_all_programs(self, controller_regex):
        s = self.session.get("{}/enteliweb/wsds/getdevicelist?ObjRef=%2F%2F*%2F*.DEV*&searchStr=".format(self.host), verify=self.verify, timeout=10)
        data = json.loads(s.text)
        program_dir = 'controller_programs'
        os.makedirs(program_dir, exist_ok=True)
        count = 0
        for key in data['deviceList']:
            for controller in data['deviceList'][key]:
                if not re.search(controller_regex, controller['Ref']):
                    continue
                try:
                    s = self.session.post("{}/enteliweb/wsdevice/objectlist".format(self.host),
                        data = {
                            "ObjRef": '["{}"]'.format(controller['Ref']),
                            "_csrfToken": self.csrf_token,
                            "query": "",
                            "sort": "ObjectInstance ASC"
                        },
                        verify=self.verify,
                        timeout=60
                    )
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error fetching objects for controller {controller['Ref']}: {e}")
                    continue
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON for controller {controller['Ref']}: {e}")
                    continue
                objects = json.loads(s.text)['objects']
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
                time.sleep(1)
        logging.info(f"Saved {count} programs to {program_dir}/")

    def collect(self):
        lines = []
        metric_name = 'enteliweb_value'
        lines.append(f'# HELP {metric_name} Current value')
        lines.append(f'# TYPE {metric_name} gauge')
        start_time = time.time()
        values, controller_timings = self.get_values(self.devices)
        end_time = time.time()

        for sorted_value in sorted(values, key=lambda x: x[0]):
            if sorted_value[1] is None:
                continue
            lines.append(f'{metric_name}{{bacnet_id="{sorted_value[0][0]}", label="{sorted_value[0][1]}"}} {sorted_value[1]}')

        lines.append(f'# HELP enteliweb_controller_duration_seconds Duration to collect values per controller')
        lines.append(f'# TYPE enteliweb_controller_duration_seconds gauge')
        for ctrl, elapsed in controller_timings:
            lines.append(f'enteliweb_controller_duration_seconds{{controller="{ctrl}"}} {elapsed:.3f}')

        lines.append(f'# HELP enteliweb_scrape_duration_seconds Duration of the scrape in seconds')
        lines.append(f'# TYPE enteliweb_scrape_duration_seconds gauge')
        lines.append(f'enteliweb_scrape_duration_seconds {end_time - start_time}')
        return '\n'.join(lines)


class MetricsHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/metrics':
            body = eweb.collect().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enteliweb exporter')
    parser.add_argument('config')
    parser.add_argument('--log-level', default='INFO')
    parser.add_argument('--debug', action='store_true', help='Print metrics to stdout and exit')
    parser.add_argument('--get-points', action='store', help='Print all points from controllers using a regex filter and exit. If "all" is specified, all points will be printed.')
    parser.add_argument('--get-programs', action='store', help='Fetch all programs from controllers using a regex filter and save to controller_program/. If "all" is specified, all programs will be fetched.')
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

    devices = []
    # create file if it doesn't exist
    if not os.path.exists(config['enteliweb']['devices_file']):
        open(config['enteliweb']['devices_file'], 'w').close()

    with open(config['enteliweb']['devices_file'], 'r') as f:
        for device in f.readlines():
            # split the line with a regex
            bacnet_id, label = re.split(r'\s*=\s*', device.strip(), maxsplit=2)
            devices.append((bacnet_id, label))
        logging.info(f"Loaded {len(devices)} devices from {config['enteliweb']['devices_file']}")

    max_workers = int(config['exporter'].get('max_workers', 5))
    eweb = EnteliwebExporter(config['enteliweb']['host'], devices, verify, max_workers)
    eweb.login(config['enteliweb']['username'], config['enteliweb']['password'])

    if args.get_points:
        if args.get_points == 'all':
            controller_regex = '.*'
        else:
            controller_regex = args.get_points
        eweb.get_all_points(controller_regex = controller_regex)
        sys.exit(0)

    if args.get_programs:
        if args.get_programs == 'all':
            controller_regex = '.*'
        else:
            controller_regex = args.get_programs
        eweb.save_all_programs(controller_regex = controller_regex)
        sys.exit(0)

    if args.debug:
        print(eweb.collect())
    else:
        httpd = http.server.HTTPServer(('', int(config['exporter']['port'])), MetricsHandler)
        logging.info(f'Serving metrics on port {config["exporter"]["port"]}')
        httpd.serve_forever()
