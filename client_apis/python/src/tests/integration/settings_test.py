#
# CARBON BLACK API TESTS - settings
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
from datetime import timedelta

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi
from helpers.auth_helper import Creds4Token
from helpers.testdata_gen import TestDataGen

cb = None


class CbApiSettingsTest(unittest.TestCase):
    initial_settings = None

    def setUp(self):
        self.initial_settings = cb.communication_settings()
        return

    def tearDown(self):
        try:
            cb.communication_settings_modify(settings=self.initial_settings)
        except Exception as ex:
            print "\nUnable to reset communication settings"
            print ex.message
        return

    def test_communication_settings_get(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        return

    # Test toggles

    def test_communication_settings_enabled(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("enabled", settings)

        result = cb.communication_settings_modify(enabled=True)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        result = cb.communication_settings_modify(enabled=False)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        settings["enabled"] = "bad_value"
        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(settings=settings)

        self.assertEqual(err.exception.response.status_code, 400)
        return

    def test_communication_settings_statistics(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("statistics", settings)

        result = cb.communication_settings_modify(statistics=True)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        result = cb.communication_settings_modify(statistics=False)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        settings["statistics"] = "bad_value"
        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(settings=settings)

        self.assertEqual(err.exception.response.status_code, 400)
        return

    def test_communication_settings_community_participation(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("community_participation", settings)

        result = cb.communication_settings_modify(community_participation=True)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        result = cb.communication_settings_modify(community_participation=False)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        settings["community_participation"] = "bad_value"
        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(settings=settings)

        self.assertEqual(err.exception.response.status_code, 400)
        return

    def test_communication_settings_mail_server_cb(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("mail_server_type", settings)

        result = cb.communication_settings_modify(mail_server_type="cb")
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")
        return

    def test_communication_settings_mail_server_none(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("mail_server_type", settings)

        result = cb.communication_settings_modify(mail_server_type="")
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        result = cb.communication_settings_modify(mail_server_type="none")
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")
        return

    def test_communication_settings_mail_server_own(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("mail_server_type", settings)

        result = cb.communication_settings_modify(
            mail_server_type="own",
            smtp_connection_type="ssl",
            smtp_server="localhost",
            smtp_port="25",
            smtp_username="username",
            smtp_password="password"
        )
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

        mail_settings = {
            "mail_server_type": "own",
            "smtp_connection_type": "ssl",
            "smtp_server": "localhost",
            "smtp_port": "25",
            "smtp_username": "username",
            "smtp_password": "password"
        }

        result = cb.communication_settings_modify(settings=mail_settings)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")
        return

    def test_communication_settings_mail_server_invalid(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("mail_server_type", settings)

        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(mail_server_type="badtype")

        self.assertEqual(err.exception.response.status_code, 400)
        return

    def test_communication_settings_mail_server_own_invalid(self):
        settings = cb.communication_settings()
        self.assertIsNotNone(settings)
        self.assertIn("mail_server_type", settings)

        mail_settings = {
            "mail_server_type": "own",
            "smtp_connection_type": "ssl",
            "smtp_server": None,
            "smtp_port": None,
            "smtp_username": None,
            "smtp_password": None
        }

        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(settings=mail_settings)

        self.assertEqual(err.exception.response.status_code, 400)

        mail_settings = {
            "mail_server_type": "own",
            "smtp_connection_type": "bad_type",
            "smtp_server": "localhost",
            "smtp_port": "25",
            "smtp_username": "username",
            "smtp_password": "password"
        }

        with self.assertRaises(requests.HTTPError) as err:
            cb.communication_settings_modify(settings=mail_settings)

        self.assertEqual(err.exception.response.status_code, 400)
        return

    def test_concurrent_license_info(self):
        end = datetime.now()
        start = end - timedelta(days=30)
        result = cb.concurrent_license_info(start, end)
        self.assertIsNotNone(result)
        return

    def test_info(self):
        result = cb.info()
        self.assertIsNotNone(result)
        return

    def test_check_for_new_feeds(self):
        result = cb.check_for_new_feeds()
        self.assertIsNotNone(result)
        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")
        return

    def test_get_platform_server_config(self):
        config = cb.get_platform_server_config()
        self.assertIsNotNone(config)
        return

    def test_get_platform_server_config_insufficient_permissions(self):
        user = TestDataGen.gen_user()
        cb.user_add_from_data(
            username=user["username"],
            password=user["password"],
            confirm_password=user["password"],
            first_name=user["first_name"],
            last_name=user["last_name"],
            teams=user["teams"],
            email=user["email"],
            global_admin=False
        )

        auth_token = Creds4Token.get_token(url, user["username"], user["password"])
        self.assertIsNotNone(auth_token)

        non_ga_cb = CbApi(server=url, ssl_verify=False, token=auth_token, client_validation_enabled=False)

        with self.assertRaises(requests.HTTPError) as err:
            non_ga_cb.get_platform_server_config()

        self.assertEqual(err.exception.response.status_code, 403)
        return


if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python settings_test.py server_url api_token"
        print "example : python settings_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
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

