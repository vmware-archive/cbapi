#!/usr/bin/env python
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Carbon Black
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
#  
#  last updated 2016-03-13 by Jon Ross jross@carbonblack.com
#    -vastly improved base64 decoding and encoded command detection
#  updated 2016-02-10 by Jon Ross jross@carbonblack.com
#


from cbapi.util.cli_helpers import main_helper
from cbapi import CbApi
import base64
import re

def main (cb, args):
  
  powershells=cb.process_search_iter('process_name:powershell.exe')
  for s in powershells:
    if s['cmdline']:
      encoded = re.search('\-[eE][nN][cC][oOdDeEcCmMaAnN]*\s([A-Za-z0-9\+/=]+)', s['cmdline'])
      if encoded != None:
        i = encoded.group(1)
        if not re.search('[a-zA-Z0-9\+/]+={1,2}$', i):
          trailingBytes = len(i) % 4
          if trailingBytes == 3:
            i = i + '='
          elif trailingBytes == 2:
            i = i + '=='
        decodedCommand = base64.standard_b64decode(i)
        try:
          a = decodedCommand.encode('ascii','replace')
          print "Powershell Decoded Command\n%s/#analyze/%s/1\n%s\n\n" % (args['server_url'],s['id'], a.replace('\0',""))
        except UnicodeError:
          print "Powershell Decoded Command\n%s/#analyze/%s/1\nNon-ASCII decoding, encoded form printed to assist more research\n%s\n" % (args['server_url'],s['id'], s['cmdline'])
          pass
            


if __name__ == "__main__":
    main_helper("Decode Powershell Encoded Commands", main, custom_required=None)
