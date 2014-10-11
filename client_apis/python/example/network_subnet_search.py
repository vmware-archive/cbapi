import sys
import struct
import socket
from optparse import OptionParser


# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

from cbapi import CbApi

class CBQuery(object):
    def __init__(self, url, token, ssl_verify):
        self.cb = CbApi(url, token=token, ssl_verify=ssl_verify)
        self.cb_url = url

    def report(self, result, subnet):

        def addressInNetwork(ip, cidr):

            net = cidr.split('/')[0]
            bits = cidr.split('/')[1]

            if int(ip) > 0: 
                ipaddr = struct.unpack('<L', socket.inet_aton(ip))[0]
            else:
                ipaddr = struct.unpack('<L', socket.inet_aton(".".join(map(lambda n: str(int(ip)>>n & 0xFF), [24,16,8,0]))))[0]
            netaddr = struct.unpack('<L', socket.inet_aton(net))[0]
            netmask = ((1L << int(bits)) - 1)
            return ipaddr & netmask == netaddr & netmask
    
        # return the events associated with this process segment
        # this will include netconns, as well as modloads, filemods, etc.
        events = self.cb.process_events(result["id"], result["segment_id"])
        
        proc = events["process"]

        # for convenience, use locals for some process metadata fields
        hostname = result.get("hostname", "<unknown>")
        process_name = result.get("process_name", "<unknown>")
        user_name = result.get("username", "<unknown>")
        process_md5 = result.get("process_md5", "<unknown>")
        cmdline = result.get("cmdline", "<unknown>")
        path = result.get("path", "<unknown>")
        procstarttime = result.get("start", "<unknown>")
        proclastupdate = result.get("last_update", "<unknown>")

        # the search criteria (netconn_count:[1 to *]) should ensure that
        # all results have at least one netconn
        if proc.has_key("netconn_complete"):

            # examine each netconn in turn
            for netconn in proc["netconn_complete"]:
                
                # split the netconn event into component parts
                # note that the port is the remote port in the case of outbound
                # netconns, and local port in the case of inbound netconns
                ts, ip, port, proto, domain, dir = netconn.split("|")
                if addressInNetwork(ip, subnet): 
                    # get the dotted-quad string representation of the ip
                    str_ip = socket.inet_ntoa(struct.pack("!i", int(ip)))
                    
                    # the underlying data model provides the protocol number
                    # convert this to human-readable strings (tcp or udp)
                    if "6" == proto:
                        proto = "tcp"
                    elif "17" == proto:
                        proto = "udp"
                   
                    # the underlying data model provides a boolean indication as to
                    # if this is an inbound or outbound network connection 
                    if "true" == dir:
                        dir = "out"
                    else:
                        dir = "in" 

                    # pring the record, using pipes as a delimiter
                    print "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|" % (procstarttime,proclastupdate,hostname, user_name, proto, str_ip, port, dir, domain, process_name, process_md5, path, cmdline)

    def strip_to_int(ip):
        """
        convert a dotted-quad string IP to the corresponding int32
        """
        return struct.unpack('<L', socket.inet_aton(ip))[0]

    def check(self, subnet, datetype, begin, end):

        # print a legend
        print "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|" % ("ProcStartTime", "ProcUpdateTime","hostname", "username", "protocol", "ip", "port", "direction", "domain",  "process name",  "process md5", "process path", "cmdline")

        # build the query string
        if not end and not begin:
            q = "ipaddr:%s" % (subnet,) 
        else:
            if not end: end = "*"
            if not begin: begin = "*"
            q = "ipaddr:%s %s:[%s TO %s]" % (subnet, datetype, begin, end)
        print q

        # begin with the first result - we'll perform the search in pages 
        # the default page size is 10 (10 reslts)
        start = 0

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
                self.report(result, subnet)

            # move forward to the next page 
            start = start + 10

def is_valid_cidr(subnet):
    """
    verifies a subnet string is properly specified in CIDR notation
    """
    try:
        components = subnet.split('/')
        if 2 != len(components):
            return False
        ip = socket.inet_aton(components[0])
        mask = int(components[1])
        return True
    except:
        return False 

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Dump all network traffic for a specific subnet with optional date range")

    # for each supported output type, add an option
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-s", "--subnet", action="store", default=None, dest="subnet",
                      help="Subnet, as specified in CIDR notation e.g. 127.0.0.1/32, to query for network traffic")
    parser.add_option("-b", "--begin", action="store", default=None, dest="begin",
                      help="Beginning date to start from Format: YYYY-MM-DD")
    parser.add_option("-e", "--end", action="store", default=None, dest="end",
                      help="Beginning date to start from Format: YYYY-MM-DD")                      
    parser.add_option("-t", "--datetype", action="store", default=None, dest="datetype",
                      help="Either Start time or Last Update Time [start|last_update]")                              
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.subnet :
        print "Missing required param."
        sys.exit(-1)
    if (opts.begin or opts.end ) and not opts.datetype:
        print "You must specify date type if utilizing a date qualifier"
        sys.exit(-1)
    if opts.datetype and (opts.datetype != "start" and opts.datetype != "last_update"):
        print "The date type has to be one of 'start' or 'last_update'"
        sys.exit(-1)
    if not is_valid_cidr(opts.subnet):
        print "The subnet must be in CIDR notation e.g. 192.168.1.0/24"
        sys.exit(-1) 

    cb = CBQuery(opts.url, opts.token, ssl_verify=opts.ssl_verify)

    cb.check(opts.subnet, opts.datetype, opts.begin, opts.end)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
