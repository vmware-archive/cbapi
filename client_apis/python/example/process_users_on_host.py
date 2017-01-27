#!/usr/bin/env python
#
#The MIT License (MIT)
##
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------
#  <Short Description>
#
#  USAGE: python process_user_list_ENHANCED.py -c https://127.0.0.1:443 -a 167b2587fbc3f6c0c488ab3ddd9d370fdb3f3dcb -n -H WIN-N15HDTS50LK
#
#  <Long Description>
#
#  last updated 2015-12-10 by Ben Tedesco btedesco@bit9.com
#
#
# in the github repo, cbapi is not in the example directory

import sys
import struct
import socket
from optparse import OptionParser
from cbapi import CbApi

class CBQuery(object):
    def __init__(self, url, token, ssl_verify):
        self.cb = CbApi(url, token=token, ssl_verify=ssl_verify)
        self.cb_url = url

    def report(self, hostname, user_dictionary):
        print ""
        print "%s | %s : %s" % ("Hostname", "Process Count", "Username")
        print "--------------------------------------------"
 
        # return the events associated with this process segment
        # this will include netconns, as well as modloads, filemods, etc.

        # for convenience, use locals for some process metadata fields
	
	for key,value in user_dictionary.items():
		print "%s | %s = %s" % (hostname, value, key)

    def check(self, hostname):
        # print a legend
	print ""
	print "--------------------------------------------"

        # build the query string
        q = "hostname:%s" % (hostname)
      
        # begin with the first result - we'll perform the search in pages 
        # the default page size is 10 (10 reslts)
        start = 0
	
	#define dictionary
	user_dictionary = dict()
 
       # loop over the entire result set
        while True:
            # get the next page of results 
            procs = self.cb.process_search(q, start=start)
      
            # if there are no results, we are done paging 
            if len(procs["results"]) == 0:
                break

            # examine each result individually
            # each result represents a single process segment
            for result in procs["results"]:
		user_name = result.get("username", "<unknown>")
				
		if user_name not in user_dictionary.keys():
			print "NEW USER found on %s : %s" % (hostname, user_name)
			user_dictionary[user_name] = 1
		else:
			user_dictionary[user_name] = user_dictionary[user_name] + 1

            # move forward to the next page 
            start = start + 10
	self.report(hostname, user_dictionary)

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Dump all usernames & associated process counts for given host.")

    # for each supported output type, add an option
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., https://127.0.0.1:443")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-H", "--hostname", action="store", default=None, dest="hostname",
                      help="Endpoint hostname to query for network traffic")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.hostname:
        print "Missing required param."
        sys.exit(-1)

    cb = CBQuery(opts.url, opts.token, ssl_verify=opts.ssl_verify)

    cb.check(opts.hostname)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
