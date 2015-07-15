import sys
import struct
import socket
import pprint
import optparse


# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add an alert for a process hit")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-q", "--query_string", action="store", default=None, dest="query_string",
                      help="Query string to search for- start with either q= or cb.q.")
    parser.add_option("-r", "--rows", action="store", default=10, dest="rows",
                      help="return this many rows, default = 10")
    parser.add_option("-s", "--start", action="store", default=0, dest="start",
                      help="start at this row. 0 by default")
    parser.add_option("-t", "--sort", action="store", default= "", dest = "sort",
                      help = "Sort rows by this field and order")
    parser.add_option("-f", "--facets", action="store_true", default = False, dest = "facets",
                      help = "Return facet results")

    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.query_string:
        print "Missing required param; must provide query string run with --help for usage, "
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    alert = cb.alert_add(opts.query_string, opts.rows, opts.start, opts.sort, opts.facets)

    print "alert_added."
    for key in alert.keys():
        print "%-20s : %s" % (key, alert[key])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
