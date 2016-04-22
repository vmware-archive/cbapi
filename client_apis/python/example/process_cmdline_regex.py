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
#  USAGE:
#    python process_cmdline_regex.py -c https://127.0.0.1:443 -a 6b5aee99c133c003b9c11e584c9958da8f8943fa -n -r .*\\.dll -C -M
#    python process_cmdline_regex.py -c https://127.0.0.1:443 -a 6b5aee99c133c003b9c11e584c9958da8f8943fa -n -r \\.dll -C
#    python process_cmdline_regex.py -c https://127.0.0.1:443 -a 6b5aee99c133c003b9c11e584c9958da8f8943fa -n -r "(rundll.*\\.dll)" -G 0
#
# EXAMPLE OUTPUT:
#
#   Displaying Report for Commandline regular expression matches
#
#   Command Line Strings Matching REGEX: (rundll.*\.dll)
#   ============================================================
#
#   rundll32.exe" "c:\windows\system32\iesetup.dll
#   rundll32.exe" c:\windows\syswow64\mscories.dll
#   rundll32.exe c:\windows\system32\werconcpl.dll
#   rundll32.exe" iedkcs32.dll
#   rundll32.exe"  "c:\windows\system32\iedkcs32.dll
#   rundll32.exe" advpack.dll
#   rundll32.exe uxtheme.dll
#   rundll32.exe" c:\windows\system32\cryptext.dll
#   --------------------------------------------
#   528 Command Line Matches:
#   Search Match Count : Command Line Match
#   --------------------------------------------
#   1 : rundll32.exe c:\windows\system32\appxdeploymentclient.dll
#   1 : rundll32.exe" "C:\Windows\System32\winethc.dll
#   2 : rundll32.exe "c:\windows\system32\netplwiz.dll
#   18 : rundll32.exe "c:\windows\uicphe.dll
#   43 : rundll32.exe C:\Windows\system32\GeneralTel.dll
#   72 : rundll32.exe" advpack.dll
#   126 : rundll32.exe" iedkcs32.dll
#   300 : rundll32.exe  "c:\windows\uicphe.dll
#
#
#   BEST PRACTICE RECCOMENDATION: Use output redirection '>' OR '>>' to send results to a text file to allow for future grep, sed, awk processing
#       python process_cmdline_regex.py -c https://127.0.0.1:443 -a 6b5aee99c133c003b9c11e584c9958da8f8943fa -n -r \\.dll -C > /tmp/script.output   
#
#   Performance Note: Given that this script parses all command line data stored in Carbon Black,
#   this script can take from several minutes to several hours to run depending upon the size of
#   your Carbon Black ER datastore & the CbER server's hardware. It is reccomended to use output
#   redirection as then you can "tail" as well as monitor the output file's size to check  the status
#   of long running queries.
#
#  last updated 2016-04-20 by Ben Tedesco bentedesco@hotmail.com
#
#  Future enhancements: 
#
#
# >>----------------------------------------------------------------------------------->

import sys
import re
import struct
import socket
import collections
import operator
from optparse import OptionParser
from cbapi import CbApi

class CBQuery(object):
    def __init__(self, url, token, ssl_verify):
        self.cb = CbApi(url, token=token, ssl_verify=ssl_verify)
        self.cb_url = url

    def report(self, rundll_query, dll_dictionary, search_match_count):
	    # CALLED BY: self.report(regex, regex_match_dictionary, search_match_count)

        print "--------------------------------------------"
        print "%s Command Line Matches:" % (search_match_count)
        print "%s : %s" % ("Search Match Count", "Command Line Match")
        print "--------------------------------------------"
 
	    #ordered_dll_dictionary = collections.OrderedDict(sorted(dll_dictionary.items()))
        ordered_dll_dictionary = sorted(dll_dictionary.items(), key=operator.itemgetter(1))
        for value in ordered_dll_dictionary:
            print "%s : %s" % (value[1], value[0])

    def check(self, regex, ignore_case, group_reference_to_match, count_flag, matches_only_flag):
	    # CALLED BY: cb.check(opts.regex, opts.ignore_case, opts.group_reference_to_match, opts.count_flag, opts.matches_only_flag)

        # print a legend
    	print ""
        print "Displaying Report for Commandline regular expression matches"
        print ""
        print "Command Line Strings Matching REGEX: %s" % (regex)
        print "============================================================"
        print ""

        # build the query string
        q = "cmdline:*"

        #define dictionary
        regex_match_dictionary = dict()
        search_match_count = 0
        
        #define regexp
        # check if we need to ignore case, if so, update regexp
        if ignore_case:
            regexp = re.compile(regex, re.IGNORECASE)
        else:
            regexp = re.compile(regex)


        for result in self.cb.process_search_iter(q):
            cmdline = result.get("cmdline", "<unknown>")
            # print "CMD: %s" % (cmdline,)

            #SEARCH FOR REGEX IN STRING!!
            if matches_only_flag:
                # print "-----MATCHES ONLY"
                search_match_result = regexp.match(cmdline)
            else:
                # print "-----EVERYTHING"
                search_match_result = regexp.search(cmdline)

            if search_match_result is not None:
                # print "cmdline: %s" % (cmdline)
                # print "result: %s" % (search_match_result)
                # print "------------------------------------"

                # Iterate TOTAL Search Match Count
                search_match_count = search_match_count + 1

                # On Match, add to dictionary
                # 1st Check group_reference_to_match flag to see if we need to add a specific Group Reference or just the entire Command Line as the regex match
                if group_reference_to_match:
                    # print "cmdline: %s" % (cmdline)
                    # print"matching GROUP: %s" % (group_reference_to_match)
                    # print"search_match_result: %s" % (search_match_result)
                    regex_match_group_reference = search_match_result.group(int(group_reference_to_match))
                    if regex_match_group_reference not in regex_match_dictionary.keys():
                        print "%s" % (regex_match_group_reference)
                        regex_match_dictionary[regex_match_group_reference] = 1
                    else:
                        regex_match_dictionary[regex_match_group_reference] = regex_match_dictionary[regex_match_group_reference] + 1
                else:
                    if cmdline not in regex_match_dictionary.keys():
                        print "%s" % (cmdline)
                        regex_match_dictionary[cmdline] = 1
                    else:
                        regex_match_dictionary[cmdline] = regex_match_dictionary[cmdline] + 1

        self.report(regex, regex_match_dictionary, search_match_count)

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Parse the command line using a regular expression (includes the options to count matches & leverage reference groups to define output). NOTE: Given that this script parses all command line data stored in Carbon Black, this script can take from several minutes to several hours to run depending upon the size of your Carbon Black ER datastore & the CbER server's hardware. It is reccomended to use output redirection as then you can tail as well as monitor the output file's size to check the status of long running queries.")

    # for each supported output type, add an option
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., https://127.0.0.1:443")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-r", "--regex", action="store", default=None, dest="regex",
                      help="Regular Expression for parsing cmdline")
    parser.add_option("-i", "--ignore-case", action="store", default=None, dest="ignore_case",
                      help="Flag to force regex to ignore character case when matching")
    parser.add_option("-G", "--group-reference-to-match", action="store", default=None, dest="group_reference_to_match",
                      help="User an integer to specify which parenthesized reference group in the regex to match")
    parser.add_option("-C", "--count", action="store_true", default=False, dest="count_flag",
                      help="Count instances of matched regex hits (in some cases, enabling this function may cause this script to run for a long time)")
    parser.add_option("-M", "--matches-only", action="store_true", default=False, dest="matches_only_flag",
                      help="Match MUST begin at the 1st character of the command line string (ASSUME ^ at start of regex)")


    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.regex:
        print "Missing required param."
        sys.exit(-1)
    #If group_reference_to_match is specified, verify it is an integer
    if opts.group_reference_to_match is not None:
        if not opts.group_reference_to_match.isdigit:
            print "group-reference-to-match argument must be defined as an integer"
            sys.exit(-1)

    cb = CBQuery(opts.url, opts.token, ssl_verify=opts.ssl_verify)

    cb.check(opts.regex, opts.ignore_case, opts.group_reference_to_match, opts.count_flag, opts.matches_only_flag)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
