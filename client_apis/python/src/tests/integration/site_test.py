#
# CARBON BLACK API TESTS - site
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
name_prefix = "Test Site"


class CbApiSiteTest(unittest.TestCase):
    def create_site(self, group_ids=[]):
        add_result = cb.site_add(
            name="%s %s" % (name_prefix, datetime.now().isoformat(' ')),
            group_ids=group_ids
        )
        self.assertGreater(add_result["id"], 0)
        return add_result["id"]

    def test_site_enum(self):
        sites = cb.site_enum()
        self.assertIsNotNone(sites)
        self.assertGreater(len(sites), 0)
        return

    def test_site_add(self):
        old_sites = cb.site_enum()
        self.assertIsNotNone(old_sites)
        self.assertGreater(len(old_sites), 0)

        self.create_site()

        new_sites = cb.site_enum()
        self.assertEqual(len(new_sites), len(new_sites) + 1)

        old_sites = cb.site_enum()
        self.assertIsNotNone(old_sites)
        self.assertGreater(len(old_sites), 0)

        # the default sensor group's ID is 0
        self.create_site(group_ids=[0])

        new_sites = cb.site_enum()
        self.assertEqual(len(new_sites), len(new_sites) + 1)
        return

    def test_site_add_invalid(self):
        old_sites = cb.site_enum()
        self.assertIsNotNone(old_sites)
        self.assertGreater(len(old_sites), 0)

        with self.assertRaises(requests.HTTPError):
            cb.site_add(name=None)

        with self.assertRaises(requests.HTTPError):
            cb.site_add(
                name="%s %s" % (name_prefix, datetime.now().isoformat(' ')),
                group_ids=["bad_id"]
            )

        new_sites = cb.site_enum()
        self.assertEqual(len(new_sites), len(old_sites))
        return

    def test_site_info(self):
        sites = cb.site_enum()
        self.assertIsNotNone(sites)
        self.assertGreater(len(sites), 0)
        for site in sites:
            result = cb.site_info(site_id=site["id"])
            self.assertIsNotNone(result)
            self.assertEqual(result["id"], site["id"])
        return

    def test_site_info_invalid(self):
        with self.assertRaises(requests.HTTPError) as err:
            cb.site_info(site_id="badid")

        with self.assertRaises(requests.HTTPError) as err:
            cb.site_info(site_id=-1)
        return

    def test_site_modify(self):
        site_id = self.create_site()

        site = cb.site_info(site_id=site_id)
        self.assertIsNotNone(site)

        old_name = site["name"]
        new_name = old_name + " Modified"
        site["name"] = new_name
        modify_result = cb.site_modify(
            site_id=site_id,
            site=site
        )
        self.assertEqual(modify_result["result"], "success")

        modified_site = cb.site_info(site_id=site_id)
        self.assertNotEqual(modified_site["name"], old_name)
        self.assertEqual(modified_site["name"], new_name)
        return

    def test_site_modify_invalid(self):
        site_id = self.create_site()

        site = cb.site_info(site_id=site_id)
        self.assertIsNotNone(site)

        old_name = site["name"]
        site["name"] = None
        with self.assertRaises(requests.HTTPError):
            cb.site_modify(
                site_id=site_id,
                site=site
            )

        site["name"] = old_name
        site["group_badid"] = "badid"
        with self.assertRaises(requests.HTTPError):
            cb.site_modify(
                site_id=site_id,
                site=site
            )
        return

    def test_site_del(self):
        initial_sites = cb.site_enum()

        site_id = self.create_site()

        sites_after_add = cb.site_enum()
        self.assertEqual(len(sites_after_add), len(initial_sites) + 1)

        cb.site_del(site_id=site_id)

        sites_after_del = cb.site_enum()
        self.assertEqual(len(sites_after_del), len(initial_sites))
        return

    def test_site_del_invalid(self):
        initial_sites = cb.site_enum()

        with self.assertRaises(requests.HTTPError):
            cb.site_del(site_id=-1)

        with self.assertRaises(requests.HTTPError):
            cb.site_del(site_id="badid")

        sites_after_del = cb.site_enum()
        self.assertEqual(len(sites_after_del), len(initial_sites) + 1)

        return

    @classmethod
    def tearDownClass(cls):
        sites = cb.site_enum()
        del_count = 0
        fail_count = 0
        for site in sites:
            if site["name"].startswith(name_prefix):
                try:
                    cb.site_del(site["id"])
                    del_count += 1
                except Exception as ex:
                    print "Unable to delete site with ID %s" % site["id"]
                    print ex.message
                    fail_count += 1

        print "\n%s test sites deleted" % del_count
        if fail_count > 0:
            print "\n%s test sites were not deleted" % fail_count
        return


if __name__ == '__main__':
    if 3 != len(sys.argv):
        print "usage   : python site_test.py server_url api_token"
        print "example : python site_test.py https://cb.my.org 3ab23b1bdhjj3jdjcjhh2kl\n"
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
