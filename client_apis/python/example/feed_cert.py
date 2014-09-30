import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Configure SSL client certificate authentication for feeds")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Feed Id")
    parser.add_option("-r", "--remove", action="store_true", default=False, dest="remove",
                      help="Remove SSL client certificate authentication for the feed specified with -i")
    parser.add_option("-C", "--certificate", action="store", default=None, dest="certificate",
                      help="SSL client certificate filename; expected to begin with \"-----BEGIN CERTIFICATE-----\"")
    parser.add_option("-K", "--key", action="store", default=None, dest="key",
                      help="SSL client key filename; expected to begin with \"-----BEGIN RSA PRIVATE KEY-----\"") 
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)

    if not opts.server_url or not opts.token:
        print "Must specify a CB server and API token with -c and -a"
        sys.exit(-1)

    if not opts.id:
        print "Must specify a feed id"
        sys.exit(-1)

    if not opts.remove and not (opts.certificate and opts.key):
      print "Missing required param; run with --help for usage"
      print "Either -C AND -K must be specified (to add SSL client certificates to a feed) or -r must be specified"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    feed = {"id": opts.id}

    if opts.remove:
        feed["ssl_client_crt"] = None 
        feed["ssl_client_key"] = None 
    else:
        feed["ssl_client_crt"] = open(opts.certificate).read().strip()
        feed["ssl_client_key"] = open(opts.key).read().strip()

    print cb.feed_modify(opts.id, feed)
    

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
