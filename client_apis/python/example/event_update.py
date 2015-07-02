__author__ = 'bwolfson'

import sys
import optparse

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Update a tagged_event's description")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--id", action = "store", default = None, dest = "id",
                      help = "id of the investigation this event is for")
    parser.add_option("-e","--tagged_event_id", action = "store", default = None, dest = "tagged_event_id",
                      help = "specific id of the tagged event to be updated")
    parser.add_option("-d", "--description", action = "store", default = "", dest = "description",
                      help = "Updated description for the event")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.id or not opts.description or not opts.tagged_event_id:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #

    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    event = cb.event_update(opts.id, opts.tagged_event_id, opts.description)
    print ""
    for key in event.keys():
        print "%-20s : %s" % (key, event[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))