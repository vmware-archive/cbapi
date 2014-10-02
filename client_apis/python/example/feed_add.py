import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new feed to the Carbon Black server")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-u", "--feed-url", action="store", default=None, dest="feed_url")
    parser.add_option("-v", "--validate_server_cert", action="store_true", default=False, dest="validate_server_cert",
                      help="Carbon Black server will verify the SSL certificate of the feed server")
    parser.add_option("-p", "--use_proxy", action="store_true", default=False, dest="use_proxy",
                      help="Carbon Black server will use configured web proxy to download feed from feed url")
    parser.add_option("-e", "--enabled", action="store_true", default=False, dest="enabled",
                      help="Enable the feed for immediate matching")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.feed_url:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    # add the feed.  The feed metadata (name, icon, etc.) will be pulled from
    # the feed itself  
    #
    results = cb.feed_add_from_url(opts.feed_url, opts.enabled, opts.validate_server_cert, opts.use_proxy)

    print
    print "-> Feed added [id=%s]" % (results['id'])
    print "   -------------------------"
    print "   Name     : %s" % (results['name'],)
    print "   Display  : %s" % (results['display_name'],)
    print

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
