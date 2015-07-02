__author__ = 'bwolfson'

import sys
import optparse
sys.path.append('../src/cbapi')
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate all binary threat intelligence hits")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-m", "--md5", action = "store", default=True, dest="md5",
                      help="md5 of the binary file")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.md5:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    does_exist = False
    binaries = cb.binary_enum()

    for binary in binaries['results']:
        if binary['md5'] == opts.md5:
            does_exist = True

    if does_exist:
        binary_hits = cb.binary_hits_enum(opts.md5)

        for hit in binary_hits:
            for key in hit.keys():
                 print "%-22s : %s" % (key, hit[key])

    else:
        print "no binary file found with md5 %s" % (opts.md5)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))