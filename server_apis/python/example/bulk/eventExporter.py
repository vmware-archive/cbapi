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
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL. e.g., http://127.0.0.1; only useful when -A is specified")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server; only useful when -A and -c are specified")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate; only useful when -c is specified.")
    parser.add_option("-o", "--outputformat", action="store", default="table", dest="outputformat",
                      help="Output format; must be one of [json|table]; default is table")
    parser.add_option("-f", "--filename", action="store", default=None, dest="filename",
                      help="Single CB sensor event log filename to process")
    parser.add_option("-d", "--directory", action="store", default=None, dest="directory",
                      help="Directory to enumerate looking for Carbon Black event log files")
    parser.add_option("-r", "--remove", action="store_true", default=False, dest="remove",
                      help="Remove event log file(s) after processing; use with caution!")
    parser.add_option("-A", "--auto", action="store_true", default=False, dest="auto",
                      help="Automatically find the event log directory from CB server config")

def lookup_host_details(sensor_id):
    """
    return a dictionary describing a sensor, as identifed by it's id
    use the documented CB API, caching the results for subsequent faster lookup

    return an empty dictionary on lookup failure 
    """
    try:

        # use the cached copy if available
        #
        if sensorid_to_details_map.has_key(sensor_id):
            return sensorid_to_details_map[sensor_id]

        # perform the lookup
        # this will fail if the CB server is not availalble, if the cb
        # api parameters are incorrect, or if the sensor id does not exists
        #
        r = requests.get("%s/api/v1/sensor/%s" % (cbapi['url'], sensor_id),
                         headers=cbapi['apitoken'], verify=cbapi['ssl_verify'])
        r.raise_for_status()
        
        # cache off the result
        #
        global sensorid_to_details_map[sensor_id] = r.json()

        return r.json()

    except:
        return {}
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
    elif "netconn" == event["type"]:
        if event.get('protocol', 17) == 6:
            proto = "tcp"
        else:
            proto = "udp"

        return "%s:%s (%s) via %s %s" % (event.get("ipv4", "<no IP>"), event["port"], event.get("domain", "<no domain>"), proto, event.get("direction", "<unknown direction>"))
    elif "childproc" == event["type"]:
        return event["created"]

    import pdb; pdb.set_trace()

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
    can be in either JSON or pipe-delimited human-readable form
    """
    if "json" == outputformat:
        pprint.pprint(event)
        return

    print "%-19s | %10s | %33s | %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event["timestamp"])),\
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
            hostinfo = {}
            processEventLogFile(os.path.join(root, filename), outputformat, remove, hostinfo)

def getEventLogDirFromCfg():
    """
    determine the directory for archived CB sensor logs based on current configuration
    """
    for line in open("/etc/cb/datastore/archive.properties").readlines():
        if line.strip().startswith('cbfs-http.log-archive.filesystem.location'):
            return line.split('=')[1].strip()

    raise Exception("Unable to determine value of the cbfs-http.log-archive.filesystem.location config option")

def processEventLogFile(filename, outputformat, remove):
    """
    read an entire event log file from disk, break it into its
    component protobuf events, re-package each protobuf event as
    json, and output 
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
    if not opts.outputformat or not (opts.filename or opts.directory or opts.auto):
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    if opts.filename:
        processEventLogFile(opts.filename, opts.outputformat, opts.remove)
    elif opts.directory:
        processEventLogDir(opts.directory, opts.outputformat, opts.remove)
    elif opts.auto:
        processEventLogDir(getEventLogDirFromCfg(), opts.outputformat, opts.remove)
