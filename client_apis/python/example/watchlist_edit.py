import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Edit the Query of an Existing Watchlist")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Watchlist ID to modify")
    parser.add_option("-q", "--query", action="store", default=None, dest="query",
                      help="New search query")
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
    print '    %-20s | %s' % ('search_query', watchlist['search_query'])
    print '\n'

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.id or not opts.query:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # ensure the query string is minimally valid
    #
    if not opts.query.startswith("q="):
        print "Query must start with 'q='.  Examples;"
        print "  q=process_name:notepad.exe"
        print "  q=-modload:kernel32.dll"
        sys.exit(0)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # edit the search query of the just-added watchlist
    #
    watchlist = { 'search_query': opts.query }
    print "-> Modifying the watchlist query..."
    cb.watchlist_modify(opts.id, watchlist)
    print "-> Watchlist modified" 

    # get record describing this watchlist  
    #
    print "-> Querying for watchlist information..."
    watchlist = cb.watchlist(opts.id)
    print "-> Watchlist queried; details:" 
    watchlist_output(watchlist)
 
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
