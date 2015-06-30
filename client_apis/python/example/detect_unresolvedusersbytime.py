__author__ = 'bwolfson'

import sys
import optparse
sys.path.append('../src/cbapi')
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate unresolved users by time")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-t", "--count", action="store", default=10, dest="count",
                      help = "OPTIONAL - Number of alerts to print, defaults to 10")
    parser.add_option("-s", "--sort", action="store", default = 'desc',
                      help = "OPTIONAL - type either 'asc' for ascending order or 'desc' for descending order, defaults to desc")

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
    unresolved_users = cb.detect_unresolvedusersbytime(opts.count, opts.sort)

    user_num = 1
    for user in unresolved_users:
        print ""
        print "User Number %s" % user_num
        print "-"*50
        user_num = user_num + 1
        for key in user.keys():
             print "%-22s : %s" % (key, user[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))