<<<<<<< HEAD
import sys
import time
import struct
import socket
import pprint
import optparse 
=======
__author__ = 'bwolfson'

import sys
import optparse
>>>>>>> 8e31e4b... added feed_action area

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

<<<<<<< HEAD
import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display information about a particular feed report")
=======
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Get the a report's info from a configured feed")
>>>>>>> 8e31e4b... added feed_action area

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
<<<<<<< HEAD
    parser.add_option("-i", "--id", action="store", default=None, dest="feedid",
                      help="Id of feed of which the specified report is a part of")
    parser.add_option("-r", "--reportid", action="store", default=None, dest="reportid",
                      help="Id of report to query; this may be alphanumeric")
    return parser

def get_ioc_counts(iocs):
    """
    returns counts of md5s, ipv4s, domains, and queries as a tuple given a feed report ioc block
    """
    return len(iocs.get('md5', [])), \
           len(iocs.get('ipv4', [])), \
           len(iocs.get('dns', [])), \
           len(iocs.get('query', []))

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.feedid or not opts.reportid:
=======
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Feed id")
    parser.add_option("-r", "--report_id", action = "store", default = None, dest = "reportid",
                      help = "Report id")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.id or not opts.reportid:
>>>>>>> 8e31e4b... added feed_action area
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

<<<<<<< HEAD
    # retrieve threat report 
    #
    report = cb.feed_report_info(opts.feedid, opts.reportid)

    # get ioc counts
    #
    count_md5s, count_ipv4s, count_domains, count_queries = get_ioc_counts(report.get('iocs', {}))

    # output the threat report details
    #
    print report["title"]
    print "-" * 80
    print

    print "  Report Summary"
    print "  %s" % ("-" * 78)
    print "  %-20s : %s" % ("Score", report["score"])
    print "  %-20s : %s" % ("Report Id", report["id"])
    print "  %-20s : %s" % ("Link", report["link"])
    print "  %-20s : %s" % ("Report Timestamp", time.strftime('%Y-%m-%d %H:%M:%S GMT', time.localtime(report["timestamp"]))) 
    print "  %-20s : %s" % ("Total IOC count", count_md5s + count_ipv4s + count_domains + count_queries)
    print

    print "  Feed Details"
    print "  %s" % ("-" * 78)
    print "  %-20s : %s" % ("Feed Name", report["feed_name"])
    print "  %-20s : %s" % ("Feed Id", report["feed_id"])
    print

    print "  Report IOCs"
    print "  %s" % ("-" * 78)
    print

    if count_md5s > 0:
        print "    MD5"
        print "    %s" % ("-" * 76)
        for md5 in report["iocs"]["md5"]:
            print "    %s" % md5
        print

    if count_ipv4s > 0:
        print "    IPv4"
        print "    %s" % ("-" * 76)
        for ipv4 in report["iocs"]["ipv4"]:
            print "    %s" % ipv4
        print

    if count_domains > 0:
        print "    Domain"
        print "    %s" % ("-" * 76)
        for domain in report["iocs"]["dns"]:
            print "    %s" % domain 
        print
    
    if count_queries > 0:
        print "    Query"
        print "    %s" % ("-" * 76)
        print "    %-18s : %s" % ("Query", report["iocs"]["query"][0]["search_query"])
        print "    %-18s : %s" % ("Index Type", report["iocs"]["query"][0]["index_type"])
        print

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
=======
    curr_feeds = cb.feed_enum()
    feed_does_exist = False

    for feed in curr_feeds:
        if int(feed['id']) == int(opts.id):
            feed_does_exist = True

    if not feed_does_exist:
        print "No feed with id %s found" % opts.id
        sys.exit(-1)

    curr_reports = cb.feed_report_enum(opts.id)
    report_does_exist = False
    for report in curr_reports:
        if opts.reportid == report['id']:
            report_does_exist = True
    if not report_does_exist:
        print "No report with id %s found" % opts.reportid
        sys.exit(-1)

    # get the feed's report info
    report_info = cb.feed_report_info(opts.id, opts.reportid)

    for key in report_info.keys():
        print "%-22s : %s" % (key, report_info[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
>>>>>>> 8e31e4b... added feed_action area
