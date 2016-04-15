#!/usr/bin/env python
#
#The MIT License (MIT)
#
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
#  Delete all watchlists >= Watchlist ID
#
#  EXAMPLE USAGE: python watchlist_remove_all_newerThanID.py -c http://127.0.0.1 -a 6b5aee99c133c003b9c11e584c9958da8f8943fa -n -i 25
#
#  <Long Description>
#  Used to automate maintenance of watchlists, can be added to a cron file to remove new superfluous watchlists
#
#  last updated 2016-04-15 by Ben Tedesco btedesco@carbonblack.com
#

import sys
import optparse
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
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="Watchlist ID's >= to delete")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.id:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    watchlists = cb.watchlist()

    watchlist_int_param = int(opts.id)

    # for each result
    for watchlist in watchlists:
	watchlist_int_id = int(watchlist['id'])
	#print "watchlist['id']: %s, opts.id: %s" % (watchlist_int_id,watchlist_int_param,)
	if watchlist_int_id >= watchlist_int_param:
		#print "MATCH: watchlist['id']: %s > opts.id: %s" % (watchlist_int_id,watchlist_int_param,)
            	print "-> Deleting watchlist [id=%s]: %s" % (watchlist_int_id,watchlist['name'],)
            	watchlist = cb.watchlist_del(watchlist_int_id)
            	print "-> Watchlist deleted" 

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
