#!/bin/env python

# usage:
#  the -p flag is the URI of the specific threat feed you wish to toggle.
#  ./feed_report_toggle.py -p https://cb1.carbonblackse.com/#threat-details/43/e6314816-dcc2-45ec-8fef-d430d4a2c7aa
import sys
import optparse
import cbapi
import pprint
import warnings

cb_servers = {
    'cb1.carbonblackse.com': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'cb2.carbonblackse.com': 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
}

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump sensor list")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store", default=False, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-p", "--parse_string", action="store", default=None, dest="parse_string",
                      help="URI of threat report to parse")
    return parser


def main():
    # builds the args structure, populating with default server and token and creating many flags
    # we will only use the -p flag here
    args = build_cli_parser()
    if not args.parse_string:
        print "Missing the url containting the Server, Feed ID and Report ID to parse."
        sys.exit(-1)

    su = args.parse_string.strip()
    su_list = su.split('/',)
    if len(su_list) != 6:
        print "Length of list from parsed url is not 6."
        print "Printing parsed url and list and exiting script."
        print args.parse_string
        print su_list
        sys.exit(-1)
    feed_host = su_list[2]
    feed_id = su_list[-2]
    report_id = su_list[-1]
    
    if not feed_host in cb_servers:
        print "%s not in list of cb_servers.  Exiting" % (feed_host)
        sys.exit(1)
    args.url = 'https://%s' % (feed_host)
    args.token = cb_servers[feed_host]

    cb = cbapi.CbApi(args.url, token=args.token, ssl_verify=args.ssl_verify)

    # retrieve threat report original threat report so we can get the name of the threat feed
    # the threat feed name will be used to locate the threat feed id on the servers
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        report = cb.feed_report_info(feed_id, report_id)
    
    feed_name = report['feed_name']
    
    updated_report = {'ids': {}, 'updates': {}}
    
    if report['is_ignored'] == True:
        updated_report['updates']['is_ignored'] = False
    elif report['is_ignored'] == False:
        updated_report['updates']['is_ignored'] = True
        
    
    for server in cb_servers.keys():
        args.url = 'https://%s' % (server)
        args.token = cb_servers[server]
        cb = cbapi.CbApi(args.url, token=args.token, ssl_verify=args.ssl_verify)
        feed_id = cb.feed_get_id_by_name(feed_name)
        updated_report['ids'] = {}
        updated_report['ids'][feed_id] = [report_id]
        url = "%s/api/v1/threat_report" % (args.url)
        r = cb.cbapi_post(url, data=json.dumps(updated_report))
        if r.status_code == 200:
            print "%s (report_id: %s) is_enabled was successfully set to %s on %s" % (report['title'], report['id'], updated_report['updates']['is_ignored'], server)
        else:
            r.raise_for_status()

if __name__ == "__main__":
    sys.exit(main())
