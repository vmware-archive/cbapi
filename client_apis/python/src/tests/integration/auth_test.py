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


class CbApiAuthTest(unittest.TestCase):
    class HeaderParamParser:
        def __init__(self, header_value):
            self.header_value = header_value
            self.header_params = header_value.split(",")

        def get_param(self, name):
            value = None
            for param in self.header_params:
                if param.find(name) > -1:
                    value = param.split("=")[1]
                    if value[0] == "\"":
                        # qop doesn't have double-quotes
                        value = value[1:-1]
                    break
            return value

    def get_token(self, server, username, password):
        auth_url = "%s/api/auth" % server

        response = requests.get(url=auth_url, verify=False)
        self.assertEqual(response.status_code, 403)

        param_parser = self.HeaderParamParser(header_value=response.headers["WWW-Authenticate"])

        cnonce = datetime.now().strftime("%Y%m%d%H%M%S%f")
        nonce = param_parser.get_param("nonce")
        realm = param_parser.get_param("realm")
        qop = param_parser.get_param("qop")

        get_response = self._calculate_response(
            method="GET",
            uri=auth_url,
            username=username,
            password=password,
            nonce=nonce,
            realm=realm,
            qop=qop,
            cnonce=cnonce
        )

        auth_header_value = self._generate_auth_header(
            auth_header=param_parser.header_value,
            get_response=get_response,
            uri=auth_url,
            username=username,
            cnonce=cnonce
        )

        response = requests.get(url=auth_url, headers={"Authorization": auth_header_value}, verify=False)

        response.raise_for_status()
        result = response.json()
        return result["auth_token"]

    def _calculate_response(self, method, uri, username, password, nonce, realm, qop, cnonce):
        a2 = method + ":" + uri
        a2md5 = hashlib.md5(a2).hexdigest()
        a1md5 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
        digest = a1md5 + ":" + nonce + ":00000001:" + cnonce + ":" + qop + ":" + a2md5
        return hashlib.md5(digest).hexdigest()

    def _generate_auth_header(self, auth_header, get_response, uri, username, cnonce):
        str_vars = (auth_header, username, uri, get_response, cnonce)
        return "%s, username=\"%s\", uri=\"%s\", response=\"%s\", nc=00000001, cnonce=\"%s\"" % str_vars

    def test_get_token(self):
        token = self.get_token(url, test_username, test_password)
        self.assertIsNotNone(token)

    def test_get_token_invalid_username(self):
        with self.assertRaises(requests.HTTPError):
            self.get_token(url, "nowaythisusernameexists", "thisismypassword")


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