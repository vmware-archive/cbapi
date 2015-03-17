#!/usr/bin/python

import os
import sys
import time
import json
import random
import pprint
import socket
import struct
import syslog
import requests
import optparse

sys.path.insert(0, "lib/")

from eventHelpers import *

sensorid_to_details_map = {}
cbapi = {}
g_output = None

class EventOutput(object):

    FORMATS = ['json', 'table', 'csv']
    DESTINATIONS = ['udp', 'tcp', 'syslog', 'file', 'stdout']

    def __init__(self, out_format, out_dest):

        if out_format not in EventOutput.FORMATS:
            raise ValueError("output format (%s) not a valid format value" % out_format)

        if out_dest not in EventOutput.DESTINATIONS:
            raise ValueError("output destination (%s) not a valid destination value" % out_dest)

        self.oformat = out_format
        self.dest = out_dest

    def _getPathFromEvent(self, event):
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

        return ""

    def format(self, event):
        if "json" == self.oformat:
            try:
                import cjson
                return cjson.encode(event)
            except Exception, e:
                return json.dumps(event)

        elif 'table' == self.oformat:
            ret = "%-19s | %-20s | %10s | %33s | %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event["timestamp"])),\
                                                        event.get('computer_name', ""),
                                                        event['type'],
                                                        event.get("md5", "").encode('hex'),
                                                        self._getPathFromEvent(event))
        elif 'csv' == self.oformat:
            ret = "%s ; %s ; %s ; %s ; %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event["timestamp"])), \
                                                        event.get('computer_name', ""),
                                                        event['type'],
                                                        event.get("md5", "").encode('hex'),
                                                        self._getPathFromEvent(event))


        return ret

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

class SyslogOutput(EventOutput):

    def __init__(self, format, identity='eventExporter.py', facility=syslog.LOG_LOCAL0, priority=syslog.LOG_INFO):
        super(SyslogOutput, self).__init__(format, 'syslog')

        self.priority = priority
        syslog.openlog(identity, syslog.LOG_PID, facility)

    def output(self, eventdata):
        syslog.syslog(self.priority, eventdata)

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

    fevent = g_output.format(event)
    g_output.output(fevent)


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

            processEventLogFile(os.path.join(root, filename), outputformat, remove, hostinfo)

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

def processEventLogFile(filename, outputformat, remove, hostinfo):
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
            event_as_obj = protobuf_to_obj(event)
           
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

def handle_event_pb(protobuf_bytes):

    (sensorid, event_obj) = protobuf_to_obj_and_host(protobuf_bytes)

    hostinnfo = lookup_host_details(sensorid)
    event_obj.update(hostinnfo)

    dumpEvent(event_obj)

def on_bus_msg(channel, method_frame, header_frame, body):
    '''
    callback that gets called for any event on the CB pub/sub event bus
    '''

    try:
        if "application/protobuf" == header_frame.content_type:
            handle_event_pb(body)

    except Exception, e:
        sys.stderr.write("-> Exception processing bus msg: %s\n" % e)

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
    # Input options (ie - where should I grab the raw events from)
    #
    group = optparse.OptionGroup(parser, "Event input source options")
    group.add_option("-i", "--in-file", action="store", default=None, dest="infile",
                      help="Single CB sensor event log filename to process")
    group.add_option("-d", "--directory", action="store", default=None, dest="directory",
                      help="Directory to enumerate looking for Carbon Black event log files")
    group.add_option("-r", "--remove", action="store_true", default=False, dest="remove",
                      help="Remove event log file(s) after processing; use with caution!")
    group.add_option("-A", "--auto", action="store_true", default=False, dest="auto",
                      help="Automatically find the event log directory from CB server config")
    group.add_option("-b", "--bus", action="store_true", default=False, dest="bus",
                      help="Pull events out of the CB pub/sub event bus")
    group.add_option("-u", "--user", action="store", default=None, dest="user",
                      help="The username for the rabbitMQ pub/sub event bus (default is to pull it from config)")
    group.add_option("-p", "--pass", action="store", default=None, dest="pwd",
                      help="The password for the rabbitMQ pub/sub event bus (default is to pull it from config)")
    parser.add_option_group(group)


    #
    # Output options (ie - where do we put the formatted events and how are they formatted)
    #
    group = optparse.OptionGroup(parser, "Output source options",
                                 "Output options for events that control both the formatting and destination")
    group.add_option("-f", "--format", action="store", default="json", dest="format",
                      help="Output format; must be one of [json|table|csv]; default is table")
    group.add_option("-o", "--out-file", action="store", default=None, dest="outfile",
                      help="Write the formatted events to a log file (default is writting to stdout)")
    group.add_option("-s", "--syslog", action="store_true", default=False, dest="syslog",
                      help="Write the formatted events to the syslog file (default is writting to stdout)")
    group.add_option('-t', '--tcp-out', action='store', default=None, dest='tcpout',
                     help='Write the formatted events to a tcp host and port (format is HOST:IP)')
    group.add_option('-U', '--udp-out', action='store', default=None, dest='udpout',
                     help='Write the formatted events to a udp host and port (format is HOST:IP)')
    parser.add_option_group(group)
    return parser



if __name__ == '__main__':

    parser = build_cli_parser()
    opts, args = parser.parse_args(sys.argv)

    # check for input
    if (not opts.infile and not opts.bus and not opts.directory and not opts.auto):
        print "Missing required input paramter.  See help (-h) for correct usage."
        sys.exit(-1)

    if opts.url is not None:
        cbapi['url'] = opts.url
    if opts.token is not None:
        cbapi['apitoken'] = opts.token
    if opts.ssl_verify is not None:
        cbapi['ssl_verify'] = opts.ssl_verify

    if (opts.outfile):
        g_output = FileOutput(opts.format, opts.outfile)
    elif (opts.syslog):
        g_output = SyslogOutput(opts.format)
    elif (opts.tcpout):
        (host, port) = opts.tcpout.split(':')
        g_output = TcpOutput(opts.format, host, int(port))
    elif (opts.udpout):
        (host, port) = opts.udpout.split(':')
        g_output = UdpOutput(opts.format, host, int(port))
    else:
        g_output = StdOutOutput(opts.format)

    if opts.infile:
        processEventLogFile(opts.filename, opts.remove)
    elif opts.directory:
        processEventLogDir(opts.directory, opts.remove)
    elif opts.auto:
        processEventLogDir(getEventLogDirFromCfg(), opts.remove)
    elif opts.bus:
        user = opts.user
        pwd = opts.pwd

        if (user is None):
            user = getBusUsernameFromConfig()

        if (pwd is None):
            pwd = getBusPasswordFromConfig()

        processEventsFromBus(user, pwd)


