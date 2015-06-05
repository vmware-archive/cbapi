#
# CARBON BLACK API TESTS - auth
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

from datetime import datetime
import hashlib
import requests
import sys
import unittest

from helpers.auth_helper import Creds4Token

class CbApiAuthTest(unittest.TestCase):

    def test_get_token(self):
        token = Creds4Token.get_token(url, test_username, test_password)
        self.assertIsNotNone(token)

    def test_get_token_invalid_username(self):
        with self.assertRaises(requests.HTTPError):
            Creds4Token.get_token(url, "nowaythisusernameexists", "thisismypassword")

if __name__ == '__main__':
    if 4 != len(sys.argv):
        print "usage   : python auth_test.py server_url username password"
        print "example : python auth_test.py https://cb.my.org admin p@ssw0rd\n"
        sys.exit(0)

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    test_password = sys.argv.pop()
    test_username = sys.argv.pop()
    url = sys.argv.pop()

    # run the unit tests
    #
    unittest.main()