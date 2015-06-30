#
# CARBON BLACK API TESTS - user
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

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi
from basetest import CbApiIntegrationTest
from helpers.auth_helper import Creds4Token
from helpers.testdata_gen import TestDataGen

class CbApiUserTest(CbApiIntegrationTest):
    def setUp(self):
        self._created_users = []

    def tearDown(self):
        for username in self._created_users:
            try:
                self.cb.user_del(username)
            except:
                print "Error while cleaning up user %s" % username

    # List user tests

    def test_list_users(self):
        users = self.cb.user_enum()
        self.assertIsNotNone(users)
        self.assertGreater(len(users), 0)

        for user in users:
            self._verify_retrieved_user(user)

    def test_list_users_as_non_ga_admin(self):
        # create a different version of CbApi using the new user's token
        user_data = TestDataGen.gen_user()
        non_ga_cb = self._create_user_and_get_api(user_data)

        users = non_ga_cb.user_enum()
        self.assertIsNotNone(users)

        # verify that no global admin is returned in the list of users
        ga_users = filter(lambda u: u['global_admin'] == True, users)
        self.assertEqual(len(ga_users) == 0)

    # Get user tests

    def test_get_unknown_user(self):
        username = "unknown-user"
        self._assert_user_doesnt_exist(username)

    def test_get_user_from_user_list(self):
        users = self.cb.user_enum()
        self.assertIsNotNone(users)
        self.assertGreater(len(users), 0)

        username = users[0]['username']
        user = self.cb.user_info(username)
        self._verify_retrieved_user(user)

    def test_get_global_admin_as_non_ga_admin(self):
        # list users and find a global admin
        users = self.cb.user_enum()
        self.assertIsNoNone(users)

        ga_users = filter(lambda u: u['global_admin'] == True, users)
        self.assertGreater(len(users), 0)
        ga_user = ga_users[0]

        # create a different version of CbApi using the new user's token
        user_data = TestDataGen.gen_user()
        non_ga_cb = self._create_user_and_get_api(user_data)

        with self.assertRaises(requests.HTTPError) as cm:
            non_ga_cb.user_info(ga_user['username'])

        self.assertEqual(cm.exception.response.status_code, 403)

    # Create user tests

    def test_create_user_no_username(self):
        user_data = TestDataGen.gen_user()

        user_add_params = self._convert_user_data_to_user_add_params(user_data)
        user_add_params['username'] = None

        # should not be able to create user with no username
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.user_add_from_data(**user_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_user_username_with_special_chars(self):
        user_data = TestDataGen.gen_user()

        user_add_params = self._convert_user_data_to_user_add_params(user_data)
        user_add_params['username'] = "testuser " + TestDataGen.gen_uid_hex()

        # should not be able to create user with a space in the username
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.user_add_from_data(**user_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_user_bad_password_confirm(self):
        user_data = TestDataGen.gen_user()

        user_add_params = self._convert_user_data_to_user_add_params(user_data)
        user_add_params['confirm_password'] = "wr0ngp@ssw0rd"

        # should not be able to create user with bad password confirmation
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.user_add_from_data(**user_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_valid_user(self):
        self._test_create_valid_user()

    def test_create_valid_global_admin(self):
        self._test_create_valid_global_admin()

    def test_create_user_duplicate_username(self):
        first_user = self._test_create_valid_user()
        self.assertIn('username', first_user)
        username = first_user['username']

        # generate second user info, but then use the same username as the first user
        second_user_data = TestDataGen.gen_user()
        second_user_data['username'] = username
        second_user_add_params = self._convert_user_data_to_user_add_params(second_user_data)

        # attempt create user with the same username
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.user_add_from_data(**second_user_add_params)

        self.assertEqual(cm.exception.response.status_code, 409)

    # Delete user tests

    def test_delete_unknown_user(self):
        username = "unknown-user"

        # verify the user does not exist on the server
        self._assert_user_doesnt_exist(username)

        # attempt to delete the user
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.user_del(username)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 400 or 404 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_delete_new_user(self):
        # create the user
        new_user = self._test_create_valid_user()
        self.assertIn('username', new_user)
        username = new_user['username']

        # verify the user exists on server
        retrieved_user = self.cb.user_info(username)
        self._verify_retrieved_user(retrieved_user)

        # delete the user
        self.cb.user_del(username)

        # verify the user no longer exists on the server
        retrieved_user = self.cb.user_info(username)
        self.assertIsNone(retrieved_user)

    def test_delete_new_global_admin(self):
        # create the global admin user
        new_user = self._test_create_valid_global_admin()
        self.assertIn('username', new_user)
        username = new_user['username']

        # verify the user exists on server
        retrieved_user = self.cb.user_info(username)
        self._verify_retrieved_user(retrieved_user)

        # delete the user
        self.cb.user_del(username)

        # verify the user no longer exists on the server
        self._assert_user_doesnt_exist(username)

    # User activity tests

    def test_get_user_activity_by_global_admin(self):
        user_activity = self.cb.user_activity()
        self.assertIsNotNone(user_activity)

        for attempt in user_activity:
            self.assertIn('username', attempt)
            self.assertIn('timestamp', attempt)
            self.assertIn('ip_address', attempt)
            self.assertIn('http_status', attempt)
            self.assertIn('http_description', attempt)

    def test_get_user_activity_as_non_ga_admin(self):
        user_data = TestDataGen.gen_user()

        # create a different version of CbApi using the new user's token
        non_ga_cb = self._create_user_and_get_api(user_data)

        # attempt to get user activity using auth token for the new user
        with self.assertRaises(requests.HTTPError) as cm:
            non_ga_cb.user_activity()

        self.assertEqual(cm.exception.response.status_code, 403)

    # Test Helpers

    def _test_create_valid_user(self):
        # generate new user data
        user_data = TestDataGen.gen_user()

        # verify the user doesn't yet exist on the server
        self._assert_user_doesnt_exist(user_data['username'])

        # create the user
        self._create_user(user_data)

        # verify the user now exists on the server
        new_user = self.cb.user_info(user_data['username'])
        self._verify_retrieved_user(new_user)
        self.assertFalse(new_user['global_admin'])

        return new_user

    def _test_create_valid_global_admin(self):
        # generate new global admin user data
        user_data = TestDataGen.gen_global_admin()

        # verify the user doesn't yet exist on the server
        self._assert_user_doesnt_exist(user_data['username'])

        self._create_user(user_data)

        # verify the user now exists on the server
        new_user = self.cb.user_info(user_data['username'])
        self._verify_retrieved_user(new_user)
        self.assertTrue(new_user['global_admin'])

        return new_user

    def _assert_user_doesnt_exist(self, username):
        with self.assertRaises(requests.HTTPError) as cm:
            retrieved_user = self.cb.user_info(username)
            self._verify_retrieved_user(retrieved_user)

        # TODO: 2015.06.01 (dplummer): not sure I would expect 500 as the error code
        self.assertEqual(cm.exception.response.status_code, 500)

    def _create_user_and_get_api(self, user_data):
        self._create_user(user_data)

        # retrieve auth token for the new user
        auth_token = Creds4Token.get_token(
            self.SERVER_URL,
            user_data['username'],
            user_data['password']
        )

        # create a different version of CbApi using the new user's token
        new_cb = CbApi(self.SERVER_URL, ssl_verify=False, token=auth_token, client_validation_enabled=False)

        return new_cb

    def _create_user(self, user_data):
        # convert new user data into params for the add-user API
        user_add_params = self._convert_user_data_to_user_add_params(user_data)

        # create the user and verify the result
        user_add_result = self.cb.user_add_from_data(**user_add_params)
        self.assertIn('result', user_add_result)
        self.assertEqual(user_add_result['result'], "success")

        self._created_users.append(user_data['username'])

    def _convert_user_data_to_user_add_params(self, user_data):
        self.assertIn('password', user_data);

        user_add_params = user_data.copy();
        user_add_params['confirm_password'] = user_add_params['password'];
        return user_add_params;

    def _verify_retrieved_user(self, user):
        self._verify_user_basic(user)
        self.assertFalse('password' in user)

    def _verify_user_basic(self, user):
        self.assertIsNotNone(user)
        self.assertIn('username', user)
        self.assertIn('teams', user)


if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python user_test.py server_url api_token"
        print "example : python user_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # set the token and server url from the arguments
    CbApiUserTest.API_TOKEN = sys.argv.pop()
    CbApiUserTest.SERVER_URL = sys.argv.pop()

    # run the unit tests
    unittest.main()