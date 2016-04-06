#!/bin/env python
# Author: bj@carbonblack.com
import optparse
import datetime
import sys
import pprint
import requests
import cbapi

requests.packages.urllib3.disable_warnings()

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
    return parser

def parent_search(opts, pdoc):
    
    opts.query = "hostname: %s process_name: %s process_pid: %d" % (pdoc['hostname'], pdoc['parent_name'], pdoc['parent_pid'])
    
    # build a cbapi object
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # use the cbapi object to iterate over all matching process documents
    try:
        r = cb.process_search(opts.query)
        identifier = r['results'][0]['id']
        seg_id = r['results'][0]['segment_id']
    except:
        return False
   
    try: 
        events = cb.process_events(identifier, seg_id)
        for cpe in events['process']['childproc_complete']: 
            cpe_split = cpe.split('|',)
            if int(cpe_split[4]) == pdoc['process_pid'] and cpe_split[5] == 'false':
                process_end_time = datetime.datetime.strptime(cpe_split[0], "%Y-%m-%d %H:%M:%S.%f")
                return process_end_time
    except:
        return False
    return False
    
def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param."
        sys.exit(-1)

    yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
    yesterday = yesterday.strftime('%Y-%m-%d')
    opts.query = 'process_name:powershell.exe and start: %s' % yesterday
    print "Initial Query: %s", opts.query
    # build a cbapi object
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)
    source_set = cb.process_search(opts.query)
    if source_set['total_results'] > 500:
        print "Total Results: %d" % source_set['total_results']
        print "More than 500 results to parse, exiting script to spare your CB server."
        sys.exit(0)

    # use the cbapi object to iterate over all matching process documents
    answer = cb.process_search_iter(opts.query)
    count = 0 
    lrcount = 0
    # iterate over each process document in the results set
    for pdoc in answer:
        count += 1
        # Query the parent process to see if this child process has ended and assign the end date to process_end_time
        process_end_time = parent_search(opts, pdoc)
        
        if process_end_time:
            end = process_end_time
        else:
            end = datetime.datetime.strptime(pdoc['last_update'], "%Y-%m-%dT%H:%M:%S.%fZ")
       
        # Start time
        start = datetime.datetime.strptime(pdoc['start'], "%Y-%m-%dT%H:%M:%S.%fZ")

        # Difference betweeen the process end time and process start time
        runtime = int((end - start).seconds)
        
        # Change the compared value if 60 seconds is not considered a long run of powershell
        if runtime > 60:
            lrcount += 1
            print "#########################"
            print "Proc Doc: %s/#/analyze/%s/%d" % (opts.url, pdoc['id'], pdoc['segment_id'])
            print "Hostname: ", pdoc['hostname']
            print "Username: ", pdoc['username']
            print "Process Name: ", pdoc['process_name']
            print "Command Line: ", pdoc['cmdline']
            print "Runtime: %d seconds" % runtime
            print "Process start  : %s" % start
            print "Process endtime: %s" % end
            print "$$$$$$$$$$$$$$$$$$$$$$$$$"
    print "Matching Process Count: ", count
    print "Matching Long Running Process Count: ", lrcount
    
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

