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
    parser.add_option("-f", "--feedname", action="store", default=None, dest="feedname",
                      help="Feed Name")

    return parser

def output_feed_info(feed):
    print feed.keys()

    print "%s" % (feed['name'])
    print "%s" % ('-' * 80,)
    for key in feed.keys():
        if not 'icon' == key:
            print "%-20s : %s" % (key, feed[key])

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.feedname:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token)

    id = cb.feed_get_id_by_name(opts.feedname)
    if id is None:
      print "-> No configured feed with name '%s' found!" % (opts.feedname) 
      return

    output_feed_info(cb.feed_info(id))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
