import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Search threat reports in configured and enabled feeds")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-q", "--query", action="store", default=None, dest="query",
                      help="threat report query e.g. feed_id:1")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or opts.query is None:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # perform a single threat report search
    #
    reports = cb.threat_report_search(opts.query)
    
    print "%-20s : %s" % ('Displayed Results', len(reports['results']))
    print "%-20s : %s" % ('Total Results', reports['total_results'])
    print "%-20s : %sms" % ('QTime', int(1000*reports['elapsed']))
    print '\n'

    # for each result 
    for report in reports['results']:
        pprint.pprint(report)
        print '\n'
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
