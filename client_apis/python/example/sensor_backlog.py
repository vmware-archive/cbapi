import sys
import time
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Output information about a single sensor")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--interval", action="store", default=0, dest="interval",
                      help="period, in seconds, in whicy to requery to use this script as a monitoring agent")
    return parser

def query_forever(cb, interval):
    
    while True:

        try:
            backlog = cb.sensor_backlog()
            print backlog
        except:
            pass 

        time.sleep(float(interval))

    return

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # if a period is specified, handle that specially
    #
    if 0 != opts.interval:
        return query_forever(cb, opts.interval)

    # grab the global statistics 
    #
    backlog = cb.sensor_backlog()

    # output
    #
    for key in backlog.keys():
        print "%-35s : %s" % (key, backlog[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
