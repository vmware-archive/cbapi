#
# CARBON BLACK API TESTS
# Copyright, Carbon Black, Inc 2013
# technology-support@carbonblack.com
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest
import sys
import os

if __name__ == '__main__':
    sys.path.insert(0, '../../')

from cbapi.cbapi import CbApi

cb = None

class CbApiTestCase(unittest.TestCase):
    def test_info(self):
        cb.info()

    def test_sensors_plain(self):
        cb.sensors()

    def test_sensors_ip_query(self):
        cb.sensors({'ip':'255.255.255.255'})

    def test_sensors_hostname_query(self):
        cb.sensors({'hostname':'unlikely_host_name'})

    def test_binary_stuff(self):
        binaries = cb.binary_search("")
        for binary in binaries['results']:
            cb.binary_summary(binary['md5'])
            cb.binary(binary['md5'])

    def test_process_stuff(self):
        processes = cb.process_search("")
        for process in processes['results']:
            process_summary = cb.process_summary(process['id'], process['segment_id'])
            process_events = cb.process_events(process['id'], process['segment_id'])

if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python cbapi.py server_url api_token"
        print "example : python cbapi.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    cb = CbApi(sys.argv[1], ssl_verify=False, token=sys.argv[2])

    # remove the server url and api token arguments, as unittest
    # itself will try to interpret them
    #
    del sys.argv[2]
    del sys.argv[1]

    # run the unit tests
    #
    unittest.main()
