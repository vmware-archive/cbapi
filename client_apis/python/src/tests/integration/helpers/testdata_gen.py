#
# CARBON BLACK API TEST HELPERS - testdata_gen
# Copyright, Bit9, Inc 2015
#

"""This is a helper to generate (in-memory) test data that can be used to pass
as argument information for various API methods
"""

import uuid

class TestDataGen:
    @staticmethod
    def gen_uid_hex():
        return uuid.uuid4().hex

    @classmethod
    def gen_user(cls):
        uid_hex = cls.gen_uid_hex()

        user = {
            'username': 'testuser' + uid_hex,
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

    @classmethod
    def gen_team(cls):
        uid_hex = cls.gen_uid_hex()

        team = {
            'name': 'Test Team ' + uid_hex,
            'group_access': []
        }
        return team

