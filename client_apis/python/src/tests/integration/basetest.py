#
# CARBON BLACK API TESTS - basetest
# Copyright, Bit9, Inc 2015
#

""" These tests require CarbonBlack Enterprise Server to be installed.
    You can run this script by passing the server URL and user API token
    as parameters.
"""

import unittest2
import sys
import os

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../")))

from cbapi.cbapi import CbApi

class CbApiIntegrationTest(unittest2.TestCase):
    SERVER_URL = None
    API_TOKEN = None

    cb = None

    @classmethod
    def setUpClass(cls):
        """Instantiate a CbApi object for integration tests.

            Args:
                cls: class object that is being setUp.
            Returns:
                None.
            Raises:
                TypeError: if SERVER_URL is not a valid URL or API_TOKEN is invalid

        """
        # instantiate a global CbApi object
        # all unit tests will use this object
        if cls.SERVER_URL is None:
            cls.SERVER_URL = os.getenv('CB_SERVER_URL')
        if cls.API_TOKEN is None:
            cls.API_TOKEN = os.getenv('CB_API_TOKEN')

        cls.cb = CbApi(cls.SERVER_URL, ssl_verify=False, token=cls.API_TOKEN, client_validation_enabled=False)
