#!/usr/bin/python

'''

 eventBusToJson - This will will listen to the carbonblack event bus and output JSON formatted messages
 of the various different events that are published to the carbon black pub/sub bus.

 This is intended as a POC usable to export all (or some) of the Carbon Black events to external notification
 and storage systems (such as Splunk) ect.

 Specific events captured are:
 - Raw sensor (endpoint) events, if enabled in the cb.conf
 - watchlist hits
 - feed hits
 - alerts
 - binary observed on hosts/group events
 - binary upload events

 See below (CAPTURE_EVENTS) to enable/disable specific event types.

 The supported output is:

 - stdout
 - a TCP or UPP socket
 - a file

'''


import os
import sys
import json
import socket
import struct
import requests
import optparse

sys.path.insert(0, "lib/")

from eventHelpers import *

sensorid_to_details_map = {}
cbapi = {}
g_output = None

g_config = {}
# highlights are a UI aide and don't make sense
# by default we will strip them out
g_config['stripHighlights'] = True
# watchlist.hit.X will coalesce multiple docs together
# we by default strip them back out and create seperate
# distinct events.   Setting this to false will leave
# them in a single message
g_config['undoWatchlistCoalesce'] = True
# print the JSON out in pretty (easily readable) format.
g_config['prettyPrint']= True

#
# what events are we going to capture on the event bus
#
# See https://github.com/carbonblack/cbapi/tree/master/server_apis
# for documentation on most of these events.
#
# Some minor changes have been made to normalize off of a single
# process guid attribute.  Generally speaking this code will attempt
# to rename attributes that are the process unique id to "process_guid"
#
# Comment out certain events here to not capture them.
#
CAPTURE_EVENTS = [
    # notifications of binaries being on
    'binary.host.observed',
    # watchlist hits - as they occur
    # see above but we break these out to per-document messages
    # they are transmitted on the bus in coalesced form
    'watchlist.hit.process',
    'watchlist.hit.binary',
    # these are just like the above but they occur when the document
    # is commited to SOLR.  This means it is visible after these notificaitons
    # occur.
    'watchlist.storage.hit.process',
    'watchlist.storage.hit.binary',
    # notifications of feed hits on ingress.  These don't have full context (process) because
    # that data is not available at ingress time
    'feed.ingress.hit.process',
    'feed.ingress.hit.binary',
    # this is a hit when a tamper event occurs and it cannot be associated with a process (such as stopping cb)
    'feed.ingress.hit.host',
    # these are just like the feeed.ingress.hit.X but occur when the document is commited to SOLR.  This means
    # there is a delay in these being published to the bus, but when they are, the document is visible and we have
    # full process context.
    'feed.storage.hit.process',
    'feed.storage.hit.binary',
    # query based feed hits
    'feed.query.hit.process',
    'feed.query.hit.binary',
    # notificaiton that a new binary has been uploaded to CB
    'binarystore.file.added',
    # alerts.  Note - feed hits and watchlist hits are both treated as watchlist.hit.X
    'alert.watchlist.hit.ingress.process',
    'alert.watchlist.hit.ingress.binary',
    # this occurs on a tamper (see feed.ingress.hit.host)
    'alert.watchlist.hit.ingress.host',
    'alert.watchlist.hit.query.process',
    'alert.watchlist.hit.query.binary',
    # raw endpoint events.
    # These need to also be enabled in cb.conf through the DatastoreBroadcastEventTypes option.
    # by default they are not enabled.   Enabling process and netconn might be a good place to start
    'ingress.event.process',
    'ingress.event.procstart',
    'ingress.event.netconn',
    'ingress.event.procend',
    'ingress.event.childproc',
    'ingress.event.moduleload',
    'ingress.event.module',
    'ingress.event.filemod',
    'ingress.event.regmod'
    ]


class EventOutput(object):

    DESTINATIONS = ['udp', 'tcp', 'file', 'stdout']

    def __init__(self, out_format, out_dest):

        if out_dest not in EventOutput.DESTINATIONS:
            raise ValueError("output destination (%s) not a valid destination value" % out_dest)

        self.oformat = out_format
        self.dest = out_dest

    def output(self, eventdata):
        raise Exception("Not Implimented")

class StdOutOutput(EventOutput):

    def __init__(self, format):
        super(StdOutOutput, self).__init__(format, 'stdout')

    def output(self, eventdata):
        print eventdata

class FileOutput(EventOutput):

    def __init__(self, format, outfile):
        super(FileOutput, self).__init__(format, 'file')

        self.fout = open(outfile, 'a')


    def output(self, eventdata):
        self.fout.write(eventdata + '\n')

class UdpOutput(EventOutput):

    def __init__(self, format, host, port):
        super(UdpOutput, self).__init__(format, 'udp')

        self.ip = socket.gethostbyname(host)
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def output(self, eventdata):
        self.sock.sendto(eventdata+'\n', (self.ip, self.port))


class TcpOutput(EventOutput):
    def __init__(self, format, host, port):
        super(TcpOutput, self).__init__(format, 'tcp')

        ip = socket.gethostbyname(host)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))

    def output(self, eventdata):
        self.sock.send(eventdata + '\n')

def lookup_host_details(sensor_id):
    """
    return a dictionary describing a sensor, as identifed by it's id
    use the documented CB API, caching the results for subsequent faster lookup

    return an empty dictionary on lookup failure 
    """
    global sensorid_to_details_map
    try:
        # without cbapi access, nothing to do
        #
        if not cbapi.has_key('url') or not cbapi.has_key('apitoken'):
            return {}
       
        # use the cached copy if available
        #
        if sensorid_to_details_map.has_key(sensor_id):
            return sensorid_to_details_map[sensor_id]
        
        # perform the lookup
        # this will fail if the CB server is not availalble, if the cb
        # api parameters are incorrect, or if the sensor id does not exists
        #
        url = "%s/api/v1/sensor/%s" % (cbapi['url'], sensor_id)
        r = requests.get(url, headers={'X-Auth-Token':cbapi['apitoken']}, verify=cbapi['ssl_verify'])
        r.raise_for_status()
        
        # cache off the result
        #

        host_details = r.json()
        
        # the sensor endpoint provides a lot more detail than is required
        # strip down to just computer name, computer sid, and sensor id
        #
        host_simple = {}
        if host_details.has_key('computer_name'):
            host_simple['computer_name'] = host_details['computer_name']
        if host_details.has_key('computer_sid'):
            host_simple['computer_sid'] = host_details['computer_sid']
        host_simple['sensor_id'] = sensor_id 
        
        # cache off the host details
        #
        sensorid_to_details_map[sensor_id] = host_simple 

        return host_simple 

    except Exception, e:
        return {}
    except:
        return {}

def dumpEvent(event):

    global g_output
    global g_config

    if (g_config['prettyPrint']):
        json_event = json.dumps(event, sort_keys=True, indent=4)
    else:
        json_event = json.dumps(event)

    g_output.output(json_event)


def processEventLogDir(directory, outputformat, remove):
    """
    recursively enumerate a directory, processing each file as a 
    Carbon Black sensor event log
    """
    for root, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            hostinfo = {}

            try:          
                sensor_id = root.split('/')[-1]
                hostinfo = lookup_host_details(sensor_id)
            except Exception, e:
                pass

            processEventLogFile(os.path.join(root, filename), outputformat, remove, hostinfo, sensor_id)

def getEventLogDirFromCfg():
    """
    determine the directory for archived CB sensor logs based on current configuration
    """
    for line in open("/etc/cb/datastore/archive.properties").readlines():
        if line.strip().startswith('cbfs-http.log-archive.filesystem.location'):
            return line.split('=')[1].strip()

    raise Exception("Unable to determine value of the cbfs-http.log-archive.filesystem.location config option")

def getBusUsernameFromConfig():
    for line in open('/etc/cb/cb.conf').readlines():
        if line.strip().startswith('RabbitMQUser'):
            return line.split('=')[1].strip()

def getBusPasswordFromConfig():
    for line in open('/etc/cb/cb.conf').readlines():
        if line.strip().startswith('RabbitMQPassword'):
            return line.split('=')[1].strip()

def processEventLogFile(filename, outputformat, remove, hostinfo, sensorid):
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
            # get the event as a native python object (dictionary)
            # this means de-protobuf-ing
            #
            event_as_obj = protobuf_to_obj(event, sensorid)
           
            event_as_obj.update(hostinfo)
 
            dumpEvent(event_as_obj)

            num_events_succeeded = num_events_succeeded + 1
        except Exception, e:
            pass

        num_events_attempted = num_events_attempted + 1

    sys.stderr.write("->   Events Sent        : %d\n" % (num_events_succeeded,))
    sys.stderr.write("->   Events Send Failed : %d\n" % (num_events_attempted - num_events_succeeded,))

    f.close()

    if remove:
        os.remove(filename)

def handle_event_pb(protobuf_bytes, routing_key):

    (sensorid, event_obj) = protobuf_to_obj_and_host(protobuf_bytes)

    hostinnfo = lookup_host_details(sensorid)
    event_obj.update(hostinnfo)

    # since we have multiple object types
    # we overwrite some fields in the protobuff based
    # event object
    event_obj['event_type'] = event_obj['type']
    event_obj['type'] = routing_key

    dumpEvent(event_obj)

def get_proc_guid_from_id(id):
    # proc guids take to forms:
    # -proc_guid
    # -proc_guid + segment_id
    #
    # This program will return the proc guid
    # and strip out the segmment id - if it exists

    parts = id.split('-')
    if (len(parts) == 6):
        parts = parts[0:5]
        return '-'.join(parts)
    else:
        return id

def fixup_proc_guids(event):


    if 'docs' in event:
        for d in event['docs']:
            if 'unique_id' in d:
                d['process_guid'] = get_proc_guid_from_id(d['unique_id'])
            if 'parent_unique_id' in d:
                d['parent_guid'] = get_proc_guid_from_id(d['parent_unique_id'])

    if ('process_id' in event):
        pid = event['process_id']
        event['process_guid'] = pid
        del event['process_id']

    return event

def handle_event_json(msg_body, routing_key):

    global g_config

    jobj = json.loads(msg_body)
    jobj['type'] = routing_key

    ret_events = []

    # for two types of alerts - the matches
    # are coalesed into a single alert
    # for our cases where we split them apart
    if (g_config['undoWatchlistCoalesce'] and routing_key.startswith('watchlist.hit.')):

        for d in jobj['docs']:
            c = jobj.copy()
            c['docs'] = [d]

            ret_events.append(c)
    else:
        ret_events.append(jobj)

    for jobj in ret_events:

        # intentionally strip highlights
        # they are more of a UI aide and don't make sense in this context
        #
        # Note: weirdness happens if we undoWatchlistCoalesce but leave
        # highlights.
        if g_config['stripHighlights'] and 'highlights' in jobj:
            del jobj['highlights']


        #
        # keep the timestamp field name consistently
        #
        if 'event_timestamp' in jobj:
            jobj['timestamp'] = jobj['event_timestamp']
            del jobj['event_timestamp']

        #
        # when it makes sense add sensor
        # information to the object.  This is dependent
        # on the object type
        #
        if (routing_key == 'watchlist.storage.hit.process' or routing_key == 'watchlist.hit.process'):
            d = jobj['docs']
            if ('sensor_id' in d):
                hinfo = lookup_host_details(d['sensor_id'])
                d.update[hinfo]

        else:
            # rather than track the correct objecsts - just look
            # for a sensor id
            if ('sensor_id' in jobj):
                hinfo = lookup_host_details(jobj['sensor_id'])
                jobj.update(hinfo)

        # fixup terminology on process id/guid so that "process_guid" always
        # refers to the process guid (minus segment)
        jobj = fixup_proc_guids(jobj)

        dumpEvent(jobj)


def on_bus_msg(channel, method_frame, header_frame, body):
    '''
    callback that gets called for any event on the CB pub/sub event bus
    '''
    try:
        # there are two messages that get broadcast that we really
        # don't care about.  They have to do with feed syncrhoniziation
        # and other internal book-keeping
        if (method_frame.routing_key not in CAPTURE_EVENTS):
            #sys.stderr.write("DBG: dropped event: %s\n" % method_frame.routing_key)
            return

        # if the type is protobuff - we handle it here
        # this means it is a raw sensor event
        if "application/protobuf" == header_frame.content_type:
            handle_event_pb(body, method_frame.routing_key)

        elif ("application/json" == header_frame.content_type):
            #handle things already in JSON
            handle_event_json(body, method_frame.routing_key)

        else:
            sys.stderr.write("->  Unexpected data type %s" % header_frame.content_type)

    except Exception, e:
        sys.stderr.write("-> Exception processing bus msg: %s\n" % e)
        #debug @todo remove me
        import traceback
        sys.stderr.write(traceback.format_exc() + "\n")

    finally:
        # need to make sure we ack the messages so they don't get left un-acked in the queue
        # we set multiple to true to ensure that we ack all previous messages
        channel.basic_ack(delivery_tag=method_frame.delivery_tag, multiple=True)

def processEventsFromBus(rabbit_mq_user, rabbit_mq_pass):

    #import this here so the other functions (file, directory)
    # work without pika installed
    import pika

    credentials = pika.PlainCredentials(rabbit_mq_user, rabbit_mq_pass)
    parameters = pika.ConnectionParameters('localhost',
                                           5004,
                                           '/',
                                           credentials)

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    queue_name = 'event_exporter_pid_%d' % os.getpid()

    # make sure you use auto_delete so the queue isn't left filling
    # with events when this program exists.
    channel.queue_declare(queue=queue_name, auto_delete=True)

    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='#')

    channel.basic_consume(on_bus_msg, queue=queue_name)

    sys.stderr.write("-> Subscribed to Pub/Sub bus (press Ctl-C to quit)\n")

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()

    connection.close()


def build_cli_parser():

    parser = optparse.OptionParser(usage="%prog [options]", description="Process Carbon Black Sensor Event Logs")

    #
    # CB server info (needed for host information lookups)
    #
    group = optparse.OptionGroup(parser, "CB server options")
    group.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL. e.g., http://127.0.0.1; only useful when -A is specified")
    group.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server; only useful when -A and -c are specified")
    group.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate; only useful when -c is specified.")
    parser.add_option_group(group)

    #
    # Bus options
    #
    group = optparse.OptionGroup(parser, "CB Bus connection options")
    group.add_option("-u", "--user", action="store", default=None, dest="user",
                      help="The username for the rabbitMQ pub/sub event bus (default is to pull it from config)")
    group.add_option("-p", "--pass", action="store", default=None, dest="pwd",
                      help="The password for the rabbitMQ pub/sub event bus (default is to pull it from config)")
    parser.add_option_group(group)

    #
    # general config options
    #
    group = optparse.OptionGroup(parser, "General Configuration")
    group.add_option("-P", "--pretty", action="store_true", default=False, dest="pretty",
                     help="Output JSON in pretty print format (easy to read) (default is False)")


    #
    # Output options (ie - where do we put the formatted events and how are they formatted)
    #
    group = optparse.OptionGroup(parser, "Output source options",
                                 "Output options for events that control both the formatting and destination")
    group.add_option("-o", "--out-file", action="store", default=None, dest="outfile",
                      help="Write the formatted events to a log file (default is writting to stdout)")
    group.add_option('-t', '--tcp-out', action='store', default=None, dest='tcpout',
                     help='Write the formatted events to a tcp host and port (format is HOST:IP)')
    group.add_option('-U', '--udp-out', action='store', default=None, dest='udpout',
                     help='Write the formatted events to a udp host and port (format is HOST:IP)')
    parser.add_option_group(group)
    return parser


if __name__ == '__main__':

    global g_config

    parser = build_cli_parser()
    opts, args = parser.parse_args(sys.argv)

    g_config['prettyPrint'] = opts.pretty

    # cbapi info for host lookups
    if opts.url is not None:
        cbapi['url'] = opts.url
    if opts.token is not None:
        cbapi['apitoken'] = opts.token
    if opts.ssl_verify is not None:
        cbapi['ssl_verify'] = opts.ssl_verify

    # output processing
    if (opts.outfile):
        g_output = FileOutput(opts.format, opts.outfile)
    elif (opts.tcpout):
        (host, port) = opts.tcpout.split(':')
        g_output = TcpOutput(opts.format, host, int(port))
    elif (opts.udpout):
        (host, port) = opts.udpout.split(':')
        g_output = UdpOutput(opts.format, host, int(port))
    else:
        g_output = StdOutOutput(opts.format)

    user = opts.user
    pwd = opts.pwd

    if (user is None):
        user = getBusUsernameFromConfig()

    if (pwd is None):
        pwd = getBusPasswordFromConfig()

    processEventsFromBus(user, pwd)


