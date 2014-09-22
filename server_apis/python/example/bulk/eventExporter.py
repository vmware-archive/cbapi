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
    parser.add_option("-d", "--directory", action="store", default=None, dest="directory",
                      help="Directory to enumerate looking for Carbon Black event log files")
    parser.add_option("-r", "--remove", action="store_true", default=False, dest="remove",
                      help="Remove event log file(s) after processing; use with caution!")
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

def getPathFromEvent(event):
    """
    Get a "path" represenation of a sensor event
    """
    if "filemod" == event["type"]:
        return event["path"]
    elif "proc" == event["type"]:
        return event["path"]
    elif "regmod" == event["type"]:
        return event["path"]
    elif "modload" == event["type"]:
        return event["path"]

    return ""

def getMd5FromEvent(event):
    """
    Get a md5 representation of a sensor event
    Only (most) process creation, modload, module (modinfo), and filewrite subtype 8 events will have an MD5
    """
    return event.get("md5", "")

def dumpEvent(event, outputformat):
    """
    dump a JSON-ified protobuf event to console for debugging
    """
    if "json" == outputformat:
        pprint.pprint(event)
        return

    print "%-19s | %12s | %33s | %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event["timestamp"])),\
                                        event['type'],\
                                        getMd5FromEvent(event),
                                        getPathFromEvent(event))

def processEventLogDir(directory, outputformat, remove):
    """
    recursively enumerate a directory, processing each file as a 
    Carbon Black sensor event log
    """
    for root, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            processEventLogFile(os.path.join(root, filename), outputformat, remove)

def processEventLogFile(filename, outputformat, remove):
    """
    read an entire event log file from disk, break it into its
    component protobuf events, re-package each protobuf event as
    json, and deliver to TCP endpoint 
    """

    sys.stderr.write("-> Processing %s...\n" % (filename,)) 
    f = open(filename)

    events = []

    while True:
        cb = f.read(4)
        if 0 == len(cb):
            break
        cb = struct.unpack('i', cb)[0]
        msg = f.read(cb)
        events.append(msg)

    sys.stderr.write("->   Read %d events\n" % (len(events),))

    num_events_attempted = 0
    num_events_succeeded = 0
 
    for event in events:

        try:
            event_as_obj = protobuf_to_obj(event)
            event_as_json = json_encode(event_as_obj)
            dumpEvent(event_as_obj, outputformat)

            num_events_succeeded = num_events_succeeded + 1
        except Exception, e:
            print e
            pass

        num_events_attempted = num_events_attempted + 1

    sys.stderr.write("->   Events Sent        : %d\n" % (num_events_succeeded,))
    sys.stderr.write("->   Events Send Failed : %d\n" % (num_events_attempted - num_events_succeeded,))

    f.close()

    if remove:
        os.remove(filename)

if __name__ == '__main__':

    parser = build_cli_parser()
    opts, args = parser.parse_args(sys.argv)
    if not opts.outputformat or not (opts.filename or opts.directory):
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    if opts.filename:
        processEventLogFile(opts.filename, opts.outputformat, opts.remove)
    elif opts.directory:
        processEventLogDir(opts.directory, opts.outputformat, opts.remove)
