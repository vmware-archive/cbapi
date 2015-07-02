import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="User Activity")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-f", "--failures", action="store_true", default= False, dest = "failures",
                      help="Show failed attempts from user to access server.") 
    parser.add_option("-s", "--successes", action="store_true", default= False, dest = "successes",
                      help="Show successful server access attempts.")    
    return parser



def output_user_activity(useractivity):
    '''
    Output all the useractivity retrieved from the server
    '''

    print "%-12s| %-14s | %-12s | %-5s | %-20s" % ("Username", "Timestamp", "Remote Ip", "Result", "Description")
    for attempt in useractivity:
        print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])


def output_user_activity_successes(useractivity):
    '''
    Output the successful user attempts to connect to server
    '''

    successes = []
    for attempt in useractivity:
        if attempt['http_status'] == 200:
            successes.append(attempt)

    print "%-12s| %-14s | %-12s | %-5s | %-20s" % ("Username", "Timestamp", "Remote Ip", "Result", "Description")
    for attempt in successes:
        print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])


def output_user_activity_failures(useractivity):
    '''
    Output the failed user attempts to connect to server
    '''
    failures = []
    for attempt in useractivity:
        if attempt['http_status'] == 403:
            failures.append(attempt)

    print "%-12s| %-14s | %-12s | %-5s | %-20s" % ("Username", "Timestamp", "Remote Ip", "Result", "Description")
    for attempt in failures:
        print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])


def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    if opts.failures and opts.successes or (not opts.failures and not opts.successes): 
        output_user_activity(cb.user_activity())
    if not opts.failures and opts.successes:
        output_user_activity_successes(cb.user_activity())
    if not opts.successes and opts.failures:
        output_user_activity_failures(cb.user_activity())

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
