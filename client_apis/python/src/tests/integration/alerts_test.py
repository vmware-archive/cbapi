#
# CARBON BLACK API TESTS - alerts
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest
import sys
import os
import json
import requests
import time

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

cb = None

class CbApiAlertTestCase(unittest.TestCase):
    def test_positive_cases(self):

        # Get All Alerts
        alerts = cb.alert_search('')
        self.assertIsNotNone(alerts)
        self.assertIsNotNone(alerts['results'])
        self.assertNotEqual(len(alerts['results']), 0)
        # print json.dumps(alerts, indent=4, sort_keys=True)

        # Search For A Specific Alert
        alerts = cb.alert_search('watch_list')
        self.assertIsNotNone(alerts)
        self.assertIsNotNone(alerts['results'])
        self.assertNotEqual(len(alerts['results']), 0)
        alert_to_update = alerts['results'][0]
        print json.dumps(alert_to_update, indent=4, sort_keys=True)

        # "Search For A Non Existing Alert
        alerts = cb.alert_search('watch_list_non')
        self.assertIsNotNone(alerts)
        self.assertEqual(len(alerts['results']), 0)

        # Update Alert
        alert_to_update['status'] = 'resolved'
        result = cb.alert_update(alert_to_update)
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], 'success')
        print json.dumps(result, indent=4, sort_keys=True)

        time.sleep(20)
        alerts = cb.alert_search('watch_list')
        self.assertIsNotNone(alerts)
        self.assertIsNotNone(alerts['results'])
        self.assertNotEqual(len(alerts['results']), 0)

        for alert in alerts['results']:
            if alert['unique_id'] == alert_to_update['unique_id']:
                self.assertEqual(alert['status'], 'Resolved')

        return

    def test_negative_cases(self):
        # /api/v1/alert/<alert_id>

        # Update Alert with wrong id in the path
        alerts = cb.alert_search('watch_list')
        self.assertIsNotNone(alerts)
        self.assertIsNotNone(alerts['results'])
        self.assertNotEqual(len(alerts['results']), 0)
        alert = alerts['results'][0]

        url = server.rstrip("/")
        token_header = {'X-Auth-Token': token}

        r = requests.post("%s/api/v1/alert/%s" % (url, alert['unique_id'] + '123'), headers=token_header,
                          data=json.dumps(alert), verify=False)
        self.assertEqual(r.status_code, 500)

        r = requests.post("%s/api/v1/alert/%s" % (url, alert['unique_id'] + '123'), headers=token_header,
                          data=json.dumps(alert), verify=False)
        self.assertEqual(r.status_code, 500)

        # GET
        r = requests.get("%s/api/v1/alert/%s" % (url, alert['unique_id']), headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)
        # DELETE
        r = requests.delete("%s/api/v1/alert/%s" % (url, alert['unique_id']), headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)
        # PUT
        r = requests.put("%s/api/v1/alert/%s" % (url, alert['unique_id']), headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)

        # /api/v1/alert

        # DELETE
        r = requests.delete("%s/api/v1/alert" % url, headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)
        # PUT
        r = requests.put("%s/api/v1/alert" % url, headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)

        # /api/v1/alerts

        # GET
        r = requests.get("%s/api/v1/alerts" % url, headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)
        # DELETE
        r = requests.delete("%s/api/v1/alerts" % url, headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)
        # PUT
        r = requests.put("%s/api/v1/alerts" % url, headers=token_header, verify=False)
        self.assertEqual(r.status_code, 405)

        # NON-AUTH
        # /api/v1/alert
        r = requests.get("%s/api/v1/alert" % url, headers='', verify=False)
        self.assertEqual(r.status_code, 403)
        # /api/v1/alert/id
        r = requests.post("%s/api/v1/alert/%s" % (url,'1234'), headers='', verify=False)
        self.assertEqual(r.status_code, 403)
        # /api/v1/alerts
        r = requests.post("%s/api/v1/alerts" % url, headers='', verify=False)
        self.assertEqual(r.status_code, 403)



if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python alerts_test.py server_url api_token"
        print "example : python alerts_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    server = sys.argv[1]
    token = sys.argv[2]
    cb = CbApi(server, ssl_verify=False, token=token)

    # remove the server url and api token arguments, as unittest
    # itself will try to interpret them
    #
    del sys.argv[2]
    del sys.argv[1]

    # run the unit tests
    #
    unittest.main()


