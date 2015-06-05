#
# CARBON BLACK API TEST HELPERS - testdata_gen
# Copyright, Bit9, Inc 2015
#

"""This is a helper for ssh commands execution
"""

import paramiko


class SSHHelper:
    @classmethod
    def execute_command(cls, server, user, password, command):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server, username=user, password=password)

        transport = client.get_transport()
        session = transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()

        session.exec_command("sudo -k %s" % command)
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        stdin.write(password +'\n')
        stdin.flush()

        for line in stdout.read().splitlines():
            print '... ' + line.strip('\n')

        client.close()
