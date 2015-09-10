#
# CARBON BLACK API TESTS - auth
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import os
import requests
import sys
import unittest2

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi
from helpers.testdata_gen import TestDataGen
from helpers.auth_helper import Creds4Token

cb = None


class CbApiAuthTest(unittest2.TestCase):

    def test_get_token(self):
        user = TestDataGen.gen_user()
        cb.user_add_from_data(
            username=user["username"],
            first_name=user["first_name"],
            last_name=user["last_name"],
            password=user["password"],
            confirm_password=user["password"],
            global_admin=False,
            teams=user["teams"],
            email=user["email"]
        )

        auth_token = Creds4Token.get_token(url, user["username"], user["password"])
        self.assertTrue(auth_token is not None)     #Replaced self.assertIsNotNone(auth_token) since it isn't python 2.6 compatible
        return

    def test_get_token_invalid_username(self):
        with self.assertRaises(requests.HTTPError) as err:
            Creds4Token.get_token(url, "nowaythisusernameexists", "thisismypassword")
        
            self.assertEqual(err.exception.response.status_code, 403)
            
        return

if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python auth_test.py server_url api_token"
        print "example : python auth_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    token = sys.argv.pop()
    url = sys.argv.pop()

    cb = CbApi(url, ssl_verify=False, token=token, client_validation_enabled=False)

    # run the unit tests
    #
    unittest2.main()
