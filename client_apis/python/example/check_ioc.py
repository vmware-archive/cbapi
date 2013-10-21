import sys

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

from cbapi import CbApi

# if you run this in a cron job, 
# put the interval here.  This uses the format
# In the last xxx minutes format.  The parser accepts
# h, m or s suffixes.

#CRON_INTERVAL = "24h"
CRON_INTERVAL = None

class CBQuery(object):
    def __init__(self, url, token):
        self.cb = CbApi(url, token=token)
        self.cb_url = url

    def report(self, ioc, type, procs, detail=False):
        for result in procs["results"]:
            # print the results to stdout. you could do anything here - 
            # log to syslog, send a SMS, fire off a siren and strobe light, etc.
            print
            print "Found %s IOC for %s in:" % (type, ioc)
            print
            print "\tPath: %s"          % result["path"]
            print "\tHostname: %s"      % result["hostname"]
            print "\tStarted: %s"       % result["start"]
            print "\tLast Updated: %s"  % result["last_update"]
            print "\tDetails: %s/#analyze/%s/%s" % (self.cb_url, result["id"], result["segment_id"])
            print

            if detail:
                self.report_detail(ioc, type, result)

    def report_detail(self, ioc, type, result):
        events = self.cb.events(result["id"], result["segment_id"])
        proc = events["process"]

        if type == "domain" and proc.has_key("netconn_complete"):
            for netconn in proc["netconn_complete"]:
                ts, ip, port, proto, domain, dir = netconn.split("|")
                if ioc in domain:
                    str_ip = socket.inet_ntoa(struct.pack("!i", int(ip)))
                    print "%s\t%s (%s:%s)" % (ts, domain, str_ip, port)

        elif type == "ipaddr" and proc.has_key("netconn_complete"):
            for netconn in proc["netconn_complete"]:
                ts, ip, port, proto, domain, direction = netconn.split("|")
                packed_ip = struct.unpack("!i", socket.inet_aton(ioc))[0]
                #import code; code.interact(local=locals())
                if packed_ip == int(ip):
                    str_ip = socket.inet_ntoa(struct.pack("!i", int(ip)))
                    print "%s\t%s (%s:%s)" % (ts, domain, str_ip, port)

        elif type == "md5" and proc.has_key("modload_complete"):
            for modload in proc["modload_complete"]:
                ts, md5, path = modload.split("|")
                if ioc in md5:
                    print "%s\t%s %s" % (ts, md5, path)

            if result["process_md5"] == ioc:
                print "%s\t%s %s" % (result["start"], result["process_md5"], result["path"])

    def check(self, iocs, type):
        # for each ioc, do a search for (type):(ioc)
        # e.g, 
        #   domain:bigfish.com
        #   md5:ce7a81ceccfa03e5e0dfd0d9a7f41466
        # 
        # additionally, if a cron interval is specified, limit searches
        # to processes updated in the last CRON_INTERVAL period
        # 
        # note - this is a very inefficient way to do this, since you test only one
        # IOC per request - you could build a large OR clause together with a few hundred
        # to efficiently and quickly check 1000s of IOCs, at the cost of increased complexity
        # when you discover a hit.

        for ioc in iocs:
            if CRON_INTERVAL:
                q = "%s:%s and last_update:-%s" % (type, ioc, CRON_INTERVAL)
            else:
                q = "%s:%s" % (type, ioc)
            procs = self.cb.processes(q)

            # if there are _any_ hits, give us the details.
            # then check the next ioc
            if len(procs["results"]) > 0:
                self.report(ioc, type, procs)
            else:
                sys.stdout.write(".")
                sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage:  check_ioc.py [cb_url] [apitoken]"
        print
        print "Example:"
        print 
        print "[irteam@localhost] python check_ioc.py http://127.0.0.1/ 3242af3...ad"
        sys.exit(1)

    # setup the CbApi object
    cb = CBQuery(sys.argv[1], sys.argv[2])

    # get the IOCs to check; this is a list of strings, one indicator
    # per line.  strip off the newlines as they come in 
    domains = [domain.strip() for domain in open("data/mandiant-domains.txt", "r")]
    md5s = [md5.strip() for md5 in open("data/mandiant-md5s.txt", "r")]

    # check each!
    cb.check(domains, "domain") 
    cb.check(md5s, "md5")

