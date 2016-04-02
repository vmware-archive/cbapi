#!/bin/env python
# A script to print all the details about a single sensor

__author__ = 'BJSwope'
import sys
import optparse
import cbapi
import pprint
import warnings

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump sensor list")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store", default=False, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-e", "--sensor", action="store", default=None, dest="sensor",
                      help="sensor id to retrieve")
    return parser


def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.sensor:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)
    
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify, ignore_system_proxy=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sensor = cb.sensor(opts.sensor)
    
    pprint.pprint(sensor)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


