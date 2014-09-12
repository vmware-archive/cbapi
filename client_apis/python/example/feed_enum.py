import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display information about an existing feed")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")

    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token)

    # enumerate configured feeds
    #
    feeds = cb.feed_enum()

    # output a banner
    #
    print "%-3s  %-15s   %-8s   %s" % ("Id", "Name", "Enabled", "Url")
    print "%s+%s+%s+%s" % ("-"*3, "-"*17, "-"*10, "-"*31)

    # output a row about each feed
    #
    for feed in feeds:
        print "%-3s| %-15s | %-8s | %s" % (feed['id'], feed['name'], feed['enabled'], feed['feed_url'])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
