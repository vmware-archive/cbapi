#
# CARBON BLACK API TESTS - team
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

from cbapi.cbapi import CbApi
from basetest import CbApiIntegrationTest
from helpers.testdata_gen import TestDataGen

class CbApiTeamTest(CbApiIntegrationTest):
    def setUp(self):
        self._created_teams = []

    def tearDown(self):
        for team_id in self._created_teams:
            try:
                self.cb.team_del(team_id)
            except:
                print "Error while cleaning up team %s" % team_id

    # List teams tests

    def test_list_teams(self):
        teams = self.cb.team_enum()
        self.assertIsNotNone(teams)
        self.assertGreater(len(teams), 0)

        for team in teams:
            self._verify_retrieved_team(team)

    # Get team tests

    def test_get_team_bad_id(self):
        team_id = "bad-id"
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_info(team_id)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 400 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_get_team_unknown_id(self):
        team_id = "-1"
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_info(team_id)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 404 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_get_team_from_team_list(self):
        teams = self.cb.team_enum()
        self.assertIsNotNone(teams)
        self.assertGreater(len(teams), 0)

        team_id = teams[0]['id']
        team = self.cb.team_info(team_id)
        self._verify_retrieved_team(team)

    # Create team tests

    def test_create_team_no_name(self):
        team_data = TestDataGen.gen_team()

        team_add_params = self._convert_team_data_to_team_add_params(team_data)
        team_add_params['team_name'] = None

        # should not be able to create team with no team name
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_add_from_data(**team_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_team_name_with_special_chars(self):
        team_data = TestDataGen.gen_team()

        team_add_params = self._convert_team_data_to_team_add_params(team_data)
        team_add_params['team_name'] = 'Test Team @' + TestDataGen.gen_uid_hex()

        # should not be able to create team with a special char in name
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_add_from_data(**team_add_params)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_create_valid_team(self):
        self._test_create_valid_team()

    def test_create_team_duplicate_name(self):
        first_team = self._test_create_valid_team()
        self.assertIn('name', first_team)
        team_name = first_team['name']

        # generate second team info, but then use the same name as the first team
        second_team_data = TestDataGen.gen_team()
        second_team_data['name'] = team_name
        second_team_add_params = self._convert_team_data_to_team_add_params(second_team_data)

        # attempt create team with the same name
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_add_from_data(**second_team_add_params)

        self.assertEqual(cm.exception.response.status_code, 409)

    # Update team tests

    def test_update_team_no_name(self):
        # create the team
        original_team = self._test_create_valid_team()
        team_id = original_team['id']

        # update the team with a new name
        updated_team = original_team.copy()
        updated_team['name'] = None

        # should not be able to update the team to have no name
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_modify(team_id, updated_team)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_update_team_name_with_special_chars(self):
        # create the team
        original_team = self._test_create_valid_team()
        team_id = original_team['id']

        # update the team with a new name
        updated_team = original_team.copy()
        updated_team['name'] = 'Test Team@' + TestDataGen.gen_uid_hex()

        # should not be able to update the team to include special chars
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_modify(team_id, updated_team)

        self.assertEqual(cm.exception.response.status_code, 400)

    def test_update_team_valid_name(self):
        # create the team
        original_team = self._test_create_valid_team()
        team_id = original_team['id']

        # update the team with a new name
        updated_team = original_team.copy()
        updated_team['name'] = 'Test Team ' + TestDataGen.gen_uid_hex()
        team_update_result = self.cb.team_modify(team_id, original_team)
        self.assertIn('result', team_update_result)
        self.assertEqual(team_update_result['result'], "success")

        # verify that the team with the ID has the updated name
        retrieved_team = self.cb.team_info(team_id)
        self._verify_retrieved_team(retrieved_team)
        self.assertNotEqual(retrieved_team['name'], original_team['name'])
        self.assertEqual(retrieved_team['name'], updated_team['name'])

        # verify that there's no longer a team with the original name
        self.assertNotEqual(original_team['name'], updated_team['name'])
        self._assert_team_doesnt_exist_by_name(original_team['name'])

        # verify that there's a team with the updated name
        retrieved_team = self.cb.team_get_team_by_name(updated_team['name'])
        self.assertIsNotNone(retrieved_team)

    def test_update_team_duplicate_name(self):
        # create the first team
        first_team = self._test_create_valid_team()

        # create the second team
        original_second_team = self._test_create_valid_team()
        second_team_id = original_second_team['id']

        # update the team with a new name
        updated_second_team = original_second_team.copy()
        updated_second_team['name'] = first_team['name']

        # should not be able to update the team to include special chars
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_modify(second_team_id, updated_second_team)

        self.assertEqual(cm.exception.response.status_code, 409)

        # verify that the team with the second team's ID still has the original name
        retrieved_team = self.cb.team_info(second_team_id)
        self._verify_retrieved_team(retrieved_team)
        self.assertNotEqual(retrieved_team['name'], updated_second_team['name'])
        self.assertEqual(retrieved_team['name'], original_second_team['name'])

        # verify that there's still a team with the second team's original name
        retrieved_team = self.cb.team_get_team_by_name(original_second_team['name'])
        self.assertIsNotNone(retrieved_team)


    # Delete team tests

    def test_delete_team_bad_id(self):
        team_id = "bad-id"
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_del(team_id)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 400 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_delete_team_unknown_id(self):
        team_id = "-1"
        with self.assertRaises(requests.HTTPError) as cm:
            self.cb.team_del(team_id)

        # TODO: 2015.06.01 (dplummer): seems like it would be better to have an HTTP 404 rather than a 500
        self.assertEqual(cm.exception.response.status_code, 500)

    def test_delete_new_team(self):
        # create the team
        new_team = self._test_create_valid_team()
        self.assertIn('id', new_team)
        team_id = new_team['id']

        # verify the team exists on the server
        retrieved_team = self.cb.team_info(team_id)
        self._verify_retrieved_team(retrieved_team)

        # delete the team
        self.cb.team_del(team_id)

        # verify the team no longer exists on the server
        self._assert_team_doesnt_exist(team_id)

    # Test Helpers

    def _test_create_valid_team(self):
        # generate new team data
        team_data = TestDataGen.gen_team()

        # verify the team doesn't yet exist on the server
        self._assert_team_doesnt_exist_by_name(team_data['name'])

        # create the team and verify the result
        new_team = self._create_team(team_data)
        self._verify_retrieved_team(new_team)

        return new_team

    def _assert_team_doesnt_exist(self, team_id):
        team = self.cb.team_info(team_id)
        self.assertIsNone(team)

    def _create_team(self, team_data):
        # convert new team data into params for the add-team API
        team_add_params = self._convert_team_data_to_team_add_params(team_data)

        # create the team and verify the result
        new_team = self.cb.team_add_from_data(**team_add_params)

        self._created_teams.append(new_team['id'])

        return new_team

    def _assert_team_doesnt_exist_by_name(self, team_name):
        team = self.cb.team_get_team_by_name(team_name)
        self.assertIsNone(team)

    def _convert_team_data_to_team_add_params(self, team_data):
        self.assertIn('name', team_data)
        self.assertIn('group_access', team_data)

        team_add_params = {}
        team_add_params['team_name'] = team_data['name']
        team_add_params['groups'] = team_data['group_access']
        return team_add_params

    def _verify_retrieved_team(self, team):
        self.assertIsNotNone(team)
        self.assertIn('id', team)
        self.assertIn('name', team)

if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python user_test.py server_url api_token"
        print "example : python user_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
        sys.exit(0)

    # set the token and server url from the arguments
    CbApiTeamTest.API_TOKEN = sys.argv.pop()
    CbApiTeamTest.SERVER_URL = sys.argv.pop()

    # run the unit tests
    unittest2.main()