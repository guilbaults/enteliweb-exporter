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

class EnteliwebExporter:
    def __init__(self, host, devices, verify):
        self.host = host
        self.session = requests.Session()
        self.devices = devices
        self.verify = verify

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

    def get_values(self, device_ids):
        device_ids_str = '.Present_Value,'.join(map(lambda x: x[0], device_ids))
        device_ids_str+='.Present_Value'
        s = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
            data = {
                "input": device_ids_str,
                "_csrfToken": self.csrf_token,
            },
            verify=self.verify,
            timeout=60
        )
        if s.status_code == 401:
            # Login again
            logging.info("Login expired, logging in again")
            self.login(self.username, self.password)
            # Try again
            s = self.session.post("{}/enteliweb/wsbacv3/getvalue".format(self.host),
                data = {
                    "input": device_ids_str,
                    "_csrfToken": self.csrf_token,
                },
                verify=self.verify,
                timeout=10
            )
            if s.status_code == 401:
                logging.error("Login failed again")
                sys.exit(1)
        if 'getcaptch' in s.text:
            logging.error("Got a captcha, lets die and retry")
            sys.exit(1)
        returned_values = s.text.lstrip('[').rstrip(']').split(',')[:-3]
        values = []
        for value in returned_values:
            try:
                v = value.strip('"')
                if v == 'inactive':
                    values.append(float(-1)) # -1 is used to indicate that the sensor is inactive
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
                    s = self.session.post("https://enteliweb.si.ulaval.ca/enteliweb/wsdevice/objectlist",
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
        with open('devices.txt', 'w') as f:
            f.write('\n'.join(lines) + '\n')
        logging.info(f"Saved {len(lines)} points to devices.txt")

    def collect(self):
        lines = []
        metric_name = 'enteliweb_value'
        lines.append(f'# HELP {metric_name} Current value')
        lines.append(f'# TYPE {metric_name} gauge')
        start_time = time.time()
        values = self.get_values(self.devices)
        end_time = time.time()

        for sorted_value in sorted(values, key=lambda x: x[0]):
            if sorted_value[1] is None:
                continue
            lines.append(f'{metric_name}{{bacnet_id="{sorted_value[0][0]}", label="{sorted_value[0][1]}"}} {sorted_value[1]}')

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
    with open(config['enteliweb']['devices_file'], 'r') as f:
        for device in f.readlines():
            # split the line with a regex
            bacnet_id, label = re.split(r'\s*=\s*', device.strip(), maxsplit=2)
            devices.append((bacnet_id, label))
        logging.info(f"Loaded {len(devices)} devices from {config['enteliweb']['devices_file']}")

    eweb = EnteliwebExporter(config['enteliweb']['host'], devices, verify)
    eweb.login(config['enteliweb']['username'], config['enteliweb']['password'])

    if args.get_points:
        if args.get_points == 'all':
            controller_regex = '.*'
        else:
            controller_regex = args.get_points
        eweb.get_all_points(controller_regex = controller_regex)
        sys.exit(0)

    if args.debug:
        print(eweb.collect())
    else:
        httpd = http.server.HTTPServer(('', int(config['exporter']['port'])), MetricsHandler)
        logging.info(f'Serving metrics on port {config["exporter"]["port"]}')
        httpd.serve_forever()
