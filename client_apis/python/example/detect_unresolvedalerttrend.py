__author__ = 'bwolfson'

import sys
import optparse
sys.path.append('../src/cbapi')
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate unresolved alert trends")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-d", "--days", action="store", default=30, dest="days",
                      help = "OPTIONAL - Number of past days of unresolved alerts to print, defaults to 30")

    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    trend = cb.detect_unresolvedalerttrend(opts.days)

    alert_num = 1
    for alert in trend['counts']:
        print ""
        print "Alert Number %s" % alert_num
        print "-"*50
        alert_num = alert_num + 1
        for key in alert.keys():
             print "%-22s : %s" % (key, alert[key])

    print ""
    print "%-22s : %s" % ("start", trend['start'])
    print "%-22s : %s" % ("end", trend['end'])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))