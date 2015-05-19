import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate all users")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    # enumerate all users
    #
    users = cb.user_enum()
    # output a banner
    #
    print "%-12s  %-14s  %-12s  %-5s  %-20s  %s" % ("username", "First Name", "Last Name","Global Administrator?","teams", "Email Address")
    print "%s+%s+%s+%s+%s+%s" % ("-"*15, "-"*20, "-"*15, "-"*8, "-"*23, "-"*25)

    # output a row about each user
    #
    for user in users:
        print "%-12s| %-14s | %-12s | %-5s | %-20s | %s" % (user['username'], user['first_name'], user['last_name'], user['global_admin'], user['teams'], user['email'])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
