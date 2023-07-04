import requests
import json
import sys
import re
import base64
import configparser
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client import make_wsgi_app
from wsgiref.simple_server import make_server, WSGIRequestHandler
import logging
import argparse

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
        for sensor in eweb.get_values(self.devices):
            if sensor[1] is not None:
                gauge_enteliweb = GaugeMetricFamily('enteliweb_' + sensor[0][1], sensor[0][2], labels=[])
                gauge_enteliweb.add_metric([], sensor[1])
                yield gauge_enteliweb


class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enteliweb exporter')
    parser.add_argument('config')
    parser.add_argument('--log-level', default='INFO')
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

    app = make_wsgi_app(eweb)
    httpd = make_server('', int(config['exporter']['port']), app)
    httpd.serve_forever()
