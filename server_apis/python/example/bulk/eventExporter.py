#!/usr/bin/python

import os
import sys
import time
import pprint
import struct
import optparse

sys.path.insert(0, "lib/")

from eventHelpers import *

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Process Carbon Black Sensor Event Logs")

    # for each supported output type, add an option
    #
    parser.add_option("-o", "--outputformat", action="store", default="table", dest="outputformat",
                      help="Output format; must be one of [json|table]; default is table")
    parser.add_option("-f", "--filename", action="store", default=None, dest="filename",
                      help="Single CB sensor event log filename to process")
    return parser

def json_encode(data):
    """
    generic json encoding logic
    uses cjson if available; json if not
    """
    try:
        import cjson
        return cjson.encode(data)
    except Exception, e:
        return json.dumps(data)

def dumpEvent(event, outputformat):
    """
    dump a JSON-ified protobuf event to console for debugging
    """
    if "json" == outputformat:
        pprint.pprint(event)
        return

    print "%-19s | %12s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event["timestamp"])),\
                            event['type'])

def processEventLogFile(filename, outputformat):
    """
    read an entire event log file from disk, break it into its
    component protobuf events, re-package each protobuf event as
    json, and deliver to TCP endpoint 
    """
 
    print "-> Opening input file [%s]..." % (filename)
    f = open(filename)

    events = []

    print "-> Reading raw protobuf log from file..."
    while True:
        cb = f.read(4)
        if 0 == len(cb):
            break
        cb = struct.unpack('i', cb)[0]
        msg = f.read(cb)
        events.append(msg)

    print "-> Read %d events" % (len(events),)
    time.sleep(1)

    one_percent = len(events) / 100 + 1   
    print '[' + '-' * 98 + ']' 

    num_events_attempted = 0
    num_events_succeeded = 0
 
    for event in events:
        if 0 == num_events_attempted % one_percent:
            sys.stdout.write('.')
            sys.stdout.flush()

        try:
            event_as_obj = protobuf_to_obj(event)
            event_as_json = json_encode(event_as_obj)
            dumpEvent(event_as_obj, outputformat)

            num_events_succeeded = num_events_succeeded + 1
        except Exception, e:
            print e
            pass

        num_events_attempted = num_events_attempted + 1

    print

    print "Events Sent        : %d" % (num_events_succeeded,)
    print "Events Send Failed : %d" % (num_events_attempted - num_events_succeeded,)

if __name__ == '__main__':

    parser = build_cli_parser()
    opts, args = parser.parse_args(sys.argv)
    if not opts.outputformat or not opts.filename:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    processEventLogFile(opts.filename, opts.outputformat)
