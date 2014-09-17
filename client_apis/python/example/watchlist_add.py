import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a watchlist")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-q", "--query", action="store", default=None, dest="query",
                      help="Watchlist query string, start with q=  e.g. q=process_name:notepad.exe")
    parser.add_option("-t", "--type", action="store", default=None, dest="type",
                      help="Watchlist type 'events' or 'modules'")
    parser.add_option("-N", "--name", action="store", default=None, dest="name",
                      help="Watchlist name")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Watchlist ID (optional)")
    parser.add_option("-r", "--readonly", action="store_true", default=False, dest="readonly",
                      help="When set, marks the new watchlist as 'read-only' so that it cannot be deleted from the console")
    return parser

def watchlist_output(watchlist):
    '''
    output information about a watchlist
    '''

    # output the details about the watchlist
    #
    print '\n'
    print '    %-20s | %s' % ('field', 'value')
    print '    %-20s + %s' % ('-' * 20, '-' * 60)
    print '    %-20s | %s' % ('id', watchlist['id'])
    print '    %-20s | %s' % ('name', watchlist['name'])
    print '    %-20s | %s' % ('date_added', watchlist['date_added'])
    print '    %-20s | %s' % ('last_hit', watchlist['last_hit'])
    print '    %-20s | %s' % ('last_hit_count', watchlist['last_hit_count'])
    print '    %-20s | %s' % ('search_query', watchlist['search_query'])
    print '    %-20s | %s' % ('readonly', watchlist['readonly'])
    print '\n'

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.name or not opts.type or not opts.query:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # baseline argument validation
    #
    if opts.type != "events" and opts.type != "modules":
        print "Watchlist type must be one of 'events' or 'modules'"
        sys.exit(-1)
    if not opts.query.startswith("q="):
        print "Query must begin with q="
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # add a watchlist
    # for the purposes of this test script, hardcode the watchlist type, name, and query string
    #
    print "-> Adding watchlist..."
    watchlist = cb.watchlist_add(opts.type, opts.name, opts.query, id=opts.id, readonly=opts.readonly)
    print "-> Watchlist added [id=%s]" % (watchlist['id'])

    # get record describing this watchlist  
    #
    print "-> Querying for watchlist information..."
    watchlist = cb.watchlist(watchlist['id'])
    print "-> Watchlist queried; details:" 
    watchlist_output(watchlist)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
