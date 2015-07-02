#
# CARBON BLACK API TESTS - server
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest
import sys
import os
import requests
from datetime import datetime

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

cb = None


class CbApiServerTest(unittest.TestCase):

    def test_get_servers(self):
        servers = cb.server_enum()
        self.assertIsNotNone(servers)
        self.assertGreater(len(servers), 0)
        return

    def test_modify_server(self):
        servers = cb.server_enum()
        self.assertIsNotNone(servers)
        self.assertGreater(len(servers), 0)

        server = servers[0]
        old_hostname = server["hostname"]
        new_hostname = old_hostname + "test"
        server["hostname"] = new_hostname

        cb.server_modify(server["node_id"], server)

        mod_servers = cb.server_enum()
        self.assertIsNotNone(mod_servers)
        self.assertGreater(len(mod_servers), 0)
        self.assertEqual(mod_servers[0]["hostname"], new_hostname)

        server["hostname"] = old_hostname

        cb.server_modify(server["node_id"], server)

        servers = cb.server_enum()
        self.assertIsNotNone(servers)
        self.assertGreater(len(servers), 0)
        self.assertEqual(servers[0]["hostname"], old_hostname)
        return

    def test_modify_server_invalid(self):

        servers = cb.server_enum()
        self.assertIsNotNone(servers)
        self.assertGreater(len(servers), 0)

        server = servers[0]

        with self.assertRaises(requests.HTTPError):
            cb.server_modify("bad_id", server)

        servers = cb.server_enum()
        self.assertIsNotNone(servers)
        self.assertGreater(len(servers), 0)

        old_address = server["address"]
        server["address"] = "baddress"

        update_failed = False
        try:
            cb.server_modify(server["node_id"], server)
        except:
            update_failed = True

        if not update_failed:
            # Clean up bad update
            server["address"] = old_address
            cb.server_modify(server["node_id"], server)
            self.fail("Bad address modification succeeded")

        return

if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python watchlist_test.py server_url api_token"
        print "example : python watchlist_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    token = sys.argv.pop()
    url = sys.argv.pop()

    cb = CbApi(url, ssl_verify=False, token=token, client_validation_enabled=False)

    # run the unit tests
    #
    unittest.main()
