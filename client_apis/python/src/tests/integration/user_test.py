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
import uuid

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

cb = None

class CbApiUserTest(unittest.TestCase):
    class TestDataGen:
        @staticmethod
        def gen_uid_hex():
            return uuid.uuid4().hex

        @classmethod
        def gen_user(cls):
            uid_hex = cls.gen_uid_hex()

            user = {
                'username': 'testuser ' + uid_hex,
                'first_name': 'IntegrationUser_' + uid_hex,
                'last_name': 'TestUser',
                'email': 'integration.testuser ' + uid_hex + '@example.com',
                'password': 'p@ssw0rd',
                'global_admin': False,
                'teams': []
            }
            return user

        @classmethod
        def gen_global_admin(cls):
            user = cls.gen_user()
            user['global_admin'] = True

            return user

    ## List user tests

    def test_list_users(self):
        users = cb.user_enum()
        self.assertIsNotNone(users)
        self.assertGreater(len(users), 0)

        for user in users:
            self._verify_retrieved_user(user)

    ## Get user tests

    def test_get_unknown_user(self):
        username = "unknown-user"
        self._assert_user_doesnt_exist(username)

    def test_get_current_user(self):
        cur_user = cb.user_info(username=None)
        self.assertIsNotNone(cur_user)

        self._verify_retrieved_user(cur_user)

    ## Create user tests

    def test_create_user_no_username(self):
        user_data = self.TestDataGen.gen_user()

        user_add_params = self._convert_user_data_to_user_add_params(user_data)
        user_add_params['username'] = None

        # should not be able to create user with no username
        with self.assertRaises(requests.HTTPError) as cm:
            cb.user_add_from_data(**user_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_user_bad_password_confirm(self):
        user_data = self.TestDataGen.gen_user()

        user_add_params = self._convert_user_data_to_user_add_params(user_data)
        user_add_params['confirm_password'] = "wr0ngp@ssw0rd"

        # should not be able to create user with bad password confirmation
        with self.assertRaises(requests.HTTPError) as cm:
            cb.user_add_from_data(**user_add_params)

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
        second_user_data = self.TestDataGen.gen_user()
        second_user_data['username'] = username
        second_user_add_params = self._convert_user_data_to_user_add_params(second_user_data)

        # attempt create user with the same username
        with self.assertRaises(requests.HTTPError) as cm:
            cb.user_add_from_data(**second_user_add_params)

        self.assertEqual(cm.exception.response.status_code, 409)

    ## Delete user tests

    def test_delete_unknown_user(self):
        username = "unknown-user"

        # verify the user does not exist on the server
        self._assert_user_doesnt_exist(username)

        # attempt to delete the user
        with self.assertRaises(requests.HTTPError) as cm:
            cb.user_del(username)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 400 or 404 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_delete_new_user(self):
        # create the user
        new_user = self._test_create_valid_user()
        self.assertIn('username', new_user)
        username = new_user['username']

        # verify the user exists on server
        retrieved_user = cb.user_info(username)
        self._verify_retrieved_user(retrieved_user)

        # delete the user
        cb.user_del(username)

        # verify the user no longer exists on the server
        retrieved_user = cb.user_info(username)
        self.assertIsNone(retrieved_user)

    def test_delete_new_global_admin(self):
        # create the global admin user
        new_user = self._test_create_valid_global_admin()
        self.assertIn('username', new_user)
        username = new_user['username']

        # verify the user exists on server
        retrieved_user = cb.user_info(username)
        self._verify_retrieved_user(retrieved_user)

        # delete the user
        cb.user_del(username)

        # verify the user no longer exists on the server
        self._assert_user_doesnt_exist(username)

    ## Test Helpers

    def _test_create_valid_user(self):
        # generate new user data
        user_data = self.TestDataGen.gen_user()

        # verify the user doesn't yet exist on the server
        self._assert_user_doesnt_exist(user_data['username'])

        # convert new user data into params for the add-user API
        user_add_params = self._convert_user_data_to_user_add_params(user_data)

        # create the user and verify the result
        user_add_result = cb.user_add_from_data(**user_add_params)
        self.assertIn('result', user_add_result)
        self.assertEqual(user_add_result['result'], "success")

        # verify the user now exists on the server
        new_user = cb.user_info(user_data['username'])
        self._verify_retrieved_user(new_user)
        self.assertFalse(new_user['global_admin'])

        return new_user

    def _test_create_valid_global_admin(self):
        # generate new global admin user data
        user_data = self.TestDataGen.gen_global_admin()

        # verify the user doesn't yet exist on the server
        self._assert_user_doesnt_exist(user_data['username'])

        # convert new user data into params for the add-user API
        user_add_params = self._convert_user_data_to_user_add_params(user_data)

        # create the user and verify the result
        user_add_result = cb.user_add_from_data(**user_add_params)
        self.assertIn('result', user_add_result)
        self.assertEqual(user_add_result['result'], "success")

        # verify the user now exists on the server
        new_user = cb.user_info(user_data['username'])
        self._verify_retrieved_user(new_user)
        self.assertTrue(new_user['global_admin'])

        return new_user

    def _assert_user_doesnt_exist(self, username):
        with self.assertRaises(requests.HTTPError) as cm:
            retrieved_user = cb.user_info(username)
            self._verify_retrieved_user(retrieved_user)

        # TODO: 2015.06.01 (dplummer): not sure I would expect 500 as the error code
        self.assertEqual(cm.exception.response.status_code, 500)

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

    # instantiate a global CbApi object
    # all unit tests will use this object
    #
    token = sys.argv.pop()
    url = sys.argv.pop()

    cb = CbApi(url, ssl_verify=False, token=token, client_validation_enabled=False)

    # run the unit tests
    #
    unittest.main()