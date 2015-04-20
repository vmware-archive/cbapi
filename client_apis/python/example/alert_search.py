import sys
import time
import struct
import socket
import optparse
#added pprint to output everything
import pprint
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Export alerts.")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-q", "--query", action="store", default="", dest="query",
                      help="The query string of alerts to search.")
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
    start = 0
    pagesize=100
    while True:
        results = cb.alert_search(opts.query, rows=int(pagesize), start=start)
        if len(results['results']) == 0: break
        for result in results['results']:
            pprint.pprint(result)
        start = start + int(pagesize)
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
