import sys
import time
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Set status to Resolved for a set of alerts.")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-q", "--query", action="store", default=None, dest="query",
                      help="The query string of alerts to resolve. All matching alerts will be resolved.")
    parser.add_option("-y", "--yes", action="store_true", default=False, dest="answered",
                      help="Automatically answer yes to any question.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.query:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    query = "-status:Resolved " + opts.query
    while True:
        results = cb.alert_search(query, rows=100)
        if results['total_results'] == 0: break

        for result in results['results']:
            new = {}
            new['unique_id'] = result['unique_id']
            new['status'] = "resolved"

            response = cb.alert_update(new)
            if not response or response['result'] != 'success':
                raise Exception("error setting status on %s: %s.  Aborting." % (result['unique_id'], repr(response)))
                break
            print "Resolved %s" % (result['unique_id'])
        time.sleep(25)
    print "Complete."
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
