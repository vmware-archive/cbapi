#
# CARBON BLACK API TEST HELPERS - auth_helper
# Copyright, Bit9, Inc 2015
#

"""This is a helper module for Cb API integration tests to interact with Cb API authentication
"""

from datetime import datetime
import hashlib
import requests

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

class Creds4Token:
    def __init__(self):
        return

    @classmethod
    def get_token(cls, server, username, password):
        """Retrieves a token for the specified user using Digest Access Authentication"""

        auth_url = "%s/api/auth" % server

        # issue a request that we expect to fail in order to retrieve a header that we'll
        # then parse for parameters
        response = requests.get(url=auth_url, verify=False)
        if not response.status_code == 403:
            raise Exception("Expected an HTTP 403, but received an HTTP %d" % response.status_code)

        param_parser = HeaderParamParser(header_value=response.headers["WWW-Authenticate"])

        cnonce = datetime.now().strftime("%Y%m%d%H%M%S%f")
        nonce = param_parser.get_param("nonce")
        realm = param_parser.get_param("realm")
        qop = param_parser.get_param("qop")

        get_response = cls._calculate_response(
            method="GET",
            uri=auth_url,
            username=username,
            password=password,
            nonce=nonce,
            realm=realm,
            qop=qop,
            cnonce=cnonce
        )

        auth_header_value = cls._generate_auth_header(
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

    @staticmethod
    def _calculate_response(method, uri, username, password, nonce, realm, qop, cnonce):
        a2 = method + ":" + uri
        a2md5 = hashlib.md5(a2).hexdigest()
        a1md5 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
        digest = a1md5 + ":" + nonce + ":00000001:" + cnonce + ":" + qop + ":" + a2md5
        return hashlib.md5(digest).hexdigest()

    @staticmethod
    def _generate_auth_header(auth_header, get_response, uri, username, cnonce):
        str_vars = (auth_header, username, uri, get_response, cnonce)
        return "%s, username=\"%s\", uri=\"%s\", response=\"%s\", nc=00000001, cnonce=\"%s\"" % str_vars
