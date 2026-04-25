import requests
import json
import sys
import re
import base64
import configparser
import logging
import argparse
import http.server

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

    def collect(self):
        values = self.get_values(self.devices)

        type_map = {'AI': 'analog_input', 'AO': 'analog_output', 'AV': 'analog_value'}
        groups = {}

        for sensor, value in values:
            if value is None:
                continue

            bacnet_id = sensor[0]
            label = sensor[1]

            suffix = re.search(r'\.(AI|AO|AV)\d+', bacnet_id, re.IGNORECASE)
            metric_type = type_map.get(suffix.group(1).upper() if suffix else '', 'gauge')

            if metric_type not in groups:
                groups[metric_type] = []
            groups[metric_type].append((bacnet_id, label, value))

        lines = []
        for metric_type in sorted(groups.keys()):
            metric_name = 'enteliweb_' + metric_type
            desc = metric_type.replace('_', ' ') + ' point'
            lines.append(f'# HELP {metric_name} Current value of {desc}')
            lines.append(f'# TYPE {metric_name} gauge')
            for bacnet_id, label, value in groups[metric_type]:
                lines.append(f'{metric_name}{{bacnet_id="{bacnet_id}", label="{label}"}} {value}')
            lines.append('')
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

    # Convert the format in the ini so the label and comment is splitted
    devices = []
    for device in list(config['devices'].items()):
        name_comment = device[1].split(',')
        modified_device = (device[0], name_comment[0], name_comment[1].strip())
        devices.append(modified_device)

    eweb = EnteliwebExporter(config['enteliweb']['host'], devices, verify)
    eweb.login(config['enteliweb']['username'], config['enteliweb']['password'])

    if args.debug:
        print(eweb.collect())
    else:
        httpd = http.server.HTTPServer(('', int(config['exporter']['port'])), MetricsHandler)
        logging.info(f'Serving metrics on port {config["exporter"]["port"]}')
        httpd.serve_forever()
