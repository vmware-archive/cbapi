#
# CARBON BLACK API TESTS - sensor
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest2
import sys
import os
import requests

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from basetest import CbApiIntegrationTest

name_prefix = "Test Sensor"

class CbApiSensorTest(CbApiIntegrationTest):
    def test_fetch_sensors_empty(self):
        sensors = self.cb.sensors()
        self.assertItemsEqual([], sensors)
        return

    def test_get_sensor_not_exist(self):
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.sensor(-1)
        self.assertEqual(cm.exception.response.status_code, 404)
        return

    def test_statistics(self):
        stats = self.cb.sensor_backlog()
        self.assertIsNotNone(stats["active_sensor_count"])
        self.assertIsNotNone(stats["sensor_count"])
        self.assertIsNotNone(stats["num_eventlog_bytes"])
        self.assertIsNotNone(stats["num_storefiles_bytes"])
        return

if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python watchlist_test.py server_url api_token"
        print "example : python watchlist_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # set the token and server url from the arguments
    CbApiSensorTest.API_TOKEN = sys.argv.pop()
    CbApiSensorTest.SERVER_URL = sys.argv.pop()

    # run the unit tests
    unittest2.main()
