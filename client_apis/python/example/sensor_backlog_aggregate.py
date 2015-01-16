import sys
import time
import json
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display, and optionally log to UDP, global sensor backlog statistics")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--interval", action="store", default=0, dest="interval",
                      help="period, in seconds, in whicy to requery to use this script as a monitoring agent")
    parser.add_option("-u", "--udp", action="store", default=None, dest="udp",
                      help="ip:port or name:port to which do deliver output via UDP, e.g. splunk.my.org:514  only applicable with -i")
    return parser

def output(data, udp):
    """
    output the sensor backlog data, in JSON format
    always output to stdout
    output to udp if so specified
    """
    print data

    if udp is None:
        return

    try:
        sockaddr_components = udp.split(':')
        ip = socket.gethostbyname(sockaddr_components[0])
        port = int(sockaddr_components[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        sock.sendto(data + '\n', (ip, port))
    except Exception, e:
        print e

    return

def query_forever(cb, interval, udp):
    
    while True:

        try:
            backlog = cb.sensor_backlog()
            output(json.dumps(backlog), udp)
        except Exception, e:
            print e
            pass 

        time.sleep(float(interval))

    return

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # if a period is specified, handle that specially
    #
    if 0 != opts.interval:
        return query_forever(cb, opts.interval, opts.udp)

    # grab the global statistics 
    #
    backlog = cb.sensor_backlog()

    # output
    #
    for key in backlog.keys():
        print "%-35s : %s" % (key, backlog[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
