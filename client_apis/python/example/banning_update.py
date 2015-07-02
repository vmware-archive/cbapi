__author__ = 'bwolfson'

import sys
import optparse
sys.path.append('../src/cbapi')
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Update the Notes field of a banned hash")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-m", "--md5", action="store", default=None, dest = "md5",
                      help = "md5 hash")
    parser.add_option("-t", "--text", action="store", default = "", dest = "text",
                      help= "Text to be displayed in the notes section")

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

    hash = cb.banning_info(opts.md5)
    if hash is None:
        print "No banned hash found with md5 hash: %s" % opts.md5
    else:
        hash = cb.banning_update(opts.md5, opts.text)
        for key in hash.keys():
            print "%-20s : %s" % (key, hash[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))