#
# CARBON BLACK API TESTS - watchlist
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
from datetime import datetime

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

cb = None
name_prefix = "Test Watchlist"


class CbApiWatchlistTest(unittest2.TestCase):
    def create_watchlist(self):
        add_result = cb.watchlist_add(
            type="modules",
            name="%s %s" % (name_prefix, datetime.now().isoformat(' ')),
            search_query="q=is_executable_image%3Afalse&cb.urlver=1&sort=server_added_timestamp%20desc",
            readonly=False
        )
        self.assertGreater(add_result["id"], 0)
        return add_result["id"]

    def test_get_watchlists(self):
        watchlists = cb.watchlist()
        self.assertIsNotNone(watchlists)
        return

    def test_add_watchlist(self):
        old_watchlists = cb.watchlist()
        self.assertIsNotNone(old_watchlists)

        self.create_watchlist()

        new_watchlists = cb.watchlist()
        self.assertEqual(len(new_watchlists), len(old_watchlists) + 1)
        return

    def test_add_invalid_watchlist(self):
        old_watchlists = cb.watchlist()
        self.assertIsNotNone(old_watchlists)
        with self.assertRaises(requests.HTTPError) as cm:
            cb.watchlist_add(
                type="bad_type",
                name="%s %s" % (name_prefix, datetime.now().isoformat(' ')),
                search_query="q=is_executable_image%3Afalse&cb.urlver=1&sort=server_added_timestamp%20desc",
                readonly=False
            )

        new_watchlists = cb.watchlist()
        self.assertEqual(len(new_watchlists), len(old_watchlists))
        return

    def test_get_watchlist(self):
        watchlists = cb.watchlist()
        self.assertIsNotNone(watchlists)
        for watchlist in watchlists:
            result = cb.watchlist(id=watchlist["id"])
            self.assertIsNotNone(result)
        return

    def test_get_invalid_watchlist(self):
        with self.assertRaises(requests.HTTPError) as err:
            cb.watchlist(id="bad_id")
        self.assertEqual(err.exception.response.status_code, 400)

        with self.assertRaises(requests.HTTPError) as err:
            cb.watchlist(id=-1)
        self.assertEqual(err.exception.response.status_code, 404)
        return

    def test_modify_watchlist(self):
        watchlist_id = self.create_watchlist()

        initial_watchlist = cb.watchlist(id=watchlist_id)
        self.assertIsNotNone(initial_watchlist)

        modifications = {"search_query": "q=is_executable_image%3Atrue&cb.urlver=1&sort=server_added_timestamp%20desc"}
        modify_result = cb.watchlist_modify(
            id=watchlist_id,
            watchlist=modifications
        )
        self.assertEqual(modify_result["result"], "success")

        modified_watchlist = cb.watchlist(id=watchlist_id)
        self.assertNotEqual(modified_watchlist["search_query"], initial_watchlist["search_query"])
        self.assertEqual(modified_watchlist["search_query"], modifications["search_query"])
        return

    def test_modify_invalid_watchlist(self):
        watchlist_id = self.create_watchlist()
        modifications = {"invalid_param": "foo"}

        with self.assertRaises(requests.HTTPError) as err:
            cb.watchlist_modify(
                id=watchlist_id,
                watchlist=modifications
            )

        self.assertEqual(err.exception.response.status_code, 500)
        return

    def test_get_actions_for_watchlist(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)
        return

    def test_add_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["id"], add_action_result["action_id"])
        return

    def test_add_invalid_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        with self.assertRaises(requests.HTTPError):
            cb.watchlist_action_add(
                watchlist_id=watchlist_id,
                action_type_id=400,
                email_recipient_user_ids=[1]
            )

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        with self.assertRaises(requests.HTTPError):
            cb.watchlist_action_add(
                watchlist_id=watchlist_id,
                action_type_id=-1,
                email_recipient_user_ids=[1]
            )

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)
        return

    def test_add_duplicate_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["id"], add_action_result["action_id"])

        with self.assertRaises(requests.HTTPError):
            cb.watchlist_action_add(
                watchlist_id=watchlist_id,
                action_type_id=0,
                email_recipient_user_ids=[1]
            )
        return

    def test_modify_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["id"], add_action_result["action_id"])
        self.assertEqual(action["action_data"], "{\"email_recipients\":[1]}")

        action["action_data"] = "{\"email_recipients\":[]}"
        modify_result = cb.watchlist_action_modify(
            watchlist_id=watchlist_id,
            action_id=action["id"],
            action=action
        )
        self.assertEqual(modify_result["result"], "success")

        new_actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(new_actions)
        self.assertEqual(len(new_actions), 1)
        self.assertEqual(new_actions[0]["id"], add_action_result["action_id"])
        self.assertEqual(new_actions[0]["action_data"], "{\"email_recipients\":[]}")
        return

    def test_modify_invalid_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["id"], add_action_result["action_id"])
        self.assertEqual(action["action_data"], "{\"email_recipients\":[1]}")

        action["action_data"] = "{\"email_recipients\":[]}"
        with self.assertRaises(requests.HTTPError) as err:
            cb.watchlist_action_modify(
                watchlist_id=watchlist_id,
                action_id=-1,
                action=action
            )
        self.assertEqual(err.exception.response.status_code, 500)

        new_actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(new_actions)
        self.assertEqual(len(new_actions), 1)
        self.assertEqual(new_actions[0]["id"], add_action_result["action_id"])
        self.assertEqual(new_actions[0]["action_data"], "{\"email_recipients\":[1]}")
        return

    def test_delete_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["id"], add_action_result["action_id"])
        self.assertEqual(actions[0]["action_data"], "{\"email_recipients\":[1]}")

        modify_result = cb.watchlist_action_del(
            watchlist_id=watchlist_id,
            action_id=add_action_result["action_id"]
        )
        self.assertEqual(modify_result["result"], "success")

        new_actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(new_actions)
        self.assertEqual(len(new_actions), 0)
        return

    def test_delete_invalid_watchlist_action(self):
        watchlist_id = self.create_watchlist()

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 0)

        add_action_result = cb.watchlist_action_add(
            watchlist_id=watchlist_id,
            action_type_id=0,
            email_recipient_user_ids=[1]
        )
        self.assertGreater(add_action_result["action_id"], 0)

        actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(actions)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["id"], add_action_result["action_id"])
        self.assertEqual(actions[0]["action_data"], "{\"email_recipients\":[1]}")

        with self.assertRaises(requests.HTTPError) as err:
            cb.watchlist_action_del(
                watchlist_id=watchlist_id,
                action_id=-1
            )
        self.assertEqual(err.exception.response.status_code, 500)

        new_actions = cb.watchlist_action_get(watchlist_id=watchlist_id)
        self.assertIsNotNone(new_actions)
        self.assertEqual(len(new_actions), 1)
        self.assertEqual(new_actions[0]["id"], add_action_result["action_id"])
        self.assertEqual(new_actions[0]["action_data"], "{\"email_recipients\":[1]}")
        return

    @classmethod
    def tearDownClass(cls):
        watchlists = cb.watchlist()
        del_count = 0
        fail_count = 0
        for watchlist in watchlists:
            if watchlist["name"].startswith(name_prefix):
                try:
                    cb.watchlist_del(watchlist["id"])
                    del_count += 1
                except:
                    print "Unable to delete watchlist with ID %s" % watchlist["id"]
                    fail_count += 1

        print "\n%s test watchlists deleted" % del_count
        if fail_count > 0:
            print "\n%s test watchlists were not deleted" % fail_count
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
    unittest2.main()
