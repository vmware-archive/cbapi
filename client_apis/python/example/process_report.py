import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump a \"report\" package for a given process")

    # for each supported output type, add an option
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-f", "--file", action="store", default=None, dest="fname",
                      help="Filename where the retrieved report is written.")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Carbon Black process identifier")
    parser.add_option("-s", "--segment", action="store", default=0, dest="segment",
                      help="Carbon Black process segment identifier")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.fname or not opts.id:
        print "Missing required param."
        sys.exit(-1)

    # setup the CbApi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    print "-> querying for report for id '%s'..." % (opts.id)
    report = cb.process_report(opts.id, opts.segment)

    print "-> writing report to file '%s'..." % (opts.fname)
    open(opts.fname, "w").write(report)

    print "-> Complete"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
