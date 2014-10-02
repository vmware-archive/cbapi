import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate all reports in a configured feed")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Id of feed of which to enumerate reports")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.id:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    # enumerate configured feeds
    #
    reports = cb.feed_report_enum(opts.id)

    # output a banner
    #
    print "%-33s  %-5s   %-8s" % ("Report Id", "Score", "Timestamp")
    print "%s+%s+%s" % ("-"*33, "-"*7, "-"*12)

    # output a row about each report 
    #
    for report in reports:
        print "%-33s| %-5s | %-8s" % (report['id'], report['score'], report['timestamp'])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
