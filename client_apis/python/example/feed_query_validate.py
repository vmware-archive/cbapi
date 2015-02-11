import sys
import json
import struct
import socket
import urllib
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Perform a process search")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-f", "--feed", action="store", default=None, dest="feed",
                      help="feed filename")
    return parser

def search_wrapper(cb, query, index):
    """
    simple search wrapper
    """

    result = {}
    result['Query'] = query

    try:
        if 'events' == index:
            results = cb.process_search(query, rows=0)
        elif 'modules' == index:
            results = cb.binary_search(query, rows=0)
        else:
            raise Exception("Unrecognized index %s" % index)

        result['TotalResults'] = results['total_results']
        result['QTime'] = int(1000*results['elapsed'])
    except Exception, e:
        result['e'] = e

    return result

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or opts.feed is None:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # read in the entire feed, decode as JSON, and store
    #
    feed = json.loads(open(opts.feed).read())

    # print a legend
    #
    print "%-20s | %-4s | %-7s | %s" % ("report id", "hits", "QTime", "Query") 
    print "%-20s | %-4s | %-7s | %s" % ("-" * 20, "-" * 4, "-" * 7, "-" * 50)

    # iterate over each report
    #
    for report in feed['reports']:
 
       # ensure report has an iocs element and skip over any reports without a query ioc
       if not report.has_key('iocs') or not report['iocs'].has_key('query'):
            continue    
 
       # ensure report has both an index_type and search_query field 
       q = report['iocs']['query'][0]
       if not q.has_key('index_type') or not q.has_key('search_query'):
           continue

       result = search_wrapper(cb, urllib.unquote(q['search_query']), q['index_type'])

       print "%-20s | %-4s | %-7s | %s" % (report.get('id', "<none>"), result['TotalResults'], str(result['QTime']) + "ms", result['Query'])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
