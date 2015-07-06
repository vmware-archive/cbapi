#
# CARBON BLACK API TESTS
# Copyright, Bit9, Inc 2014
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest
import sys
import os

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

cb = None

class CbApiTestCase(unittest.TestCase):
    def test_info(self):
        cb.info()

    def test_license(self):
        cb.license_status()

    def test_sensors_plain(self):
        cb.sensors()

    def test_sensors_ip_query(self):
        cb.sensors({'ip':'255.255.255.255'})

    def test_sensors_hostname_query(self):
        cb.sensors({'hostname':'unlikely_host_name'})

    def test_sensors_groupid(self):
        """
        verify that the count of sensors for a "bogus" group id is 0
        verify that the count of sensors for the default group (id=1) is <= total sensor count
        """
        unfiltered_count = cb.sensors()
        bogus_count = cb.sensors({'groupid': 1111111})
        default_group_count = cb.sensors({'groupid': 1})
 
        if bogus_count > 0:
            # group id filtering not enforced until CB 5.1 (see CBAPI-8)
            raise Exception("count of sensors in bogus group unexpectedly non-zero")

        if default_group_count > unfiltered_count or \
           bogus_count > unfiltered_count:
            raise Exception("count mismatch in sensors listing")

    def test_binary_stuff(self):
        binaries = cb.binary_search("", rows=5)
        num_binaries_downloaded = 0
        last_exception = None
        for binary in binaries['results']:
            cb.binary_summary(binary['md5'])
            try:
                cb.binary(binary['md5'])
                num_binaries_downloaded = num_binaries_downloaded + 1
            except Exception, e:
                last_exception = e

        # depending on the test environment (server configuration, etc.), it
        # is possible that the first ten binaries retreived via the binary_search call
        # cannot all be downloaded from the server
        #
        # only fail the test if none of the binaries can be downloaded
        #
        if 0 == num_binaries_downloaded:
            if last_exception:
                raise last_exception
            else:
                raise Exception("0 downloaded binaries!")

    def test_process_stuff(self):
        processes = cb.process_search("")
        for process in processes['results']:
            process_summary = cb.process_summary(process['id'], process['segment_id'])
            process_events = cb.process_events(process['id'], process['segment_id'])

    def test_watchlist_stuff(self):
        watchlists = cb.watchlist()
        for watchlist in watchlists:
            cb.watchlist(watchlist['id'])

    def test_platform_server_stuff(self):
        results = cb.get_platform_server_config()
        for key in ["auth_token_set", "ssl_certificate_verify", "watchlist_export"]:
            if not results.has_key(key):
                raise CbException("PlatformServer results missing key %s" % (key,))

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

