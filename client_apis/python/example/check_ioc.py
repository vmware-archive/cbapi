import sys
from cbapi import CbApi

# if you run this in a cron job, 
# put the interval here.  This uses the format
# In the last xxx minutes format.  The parser accepts
# h, m or s suffixes.

#CRON_INTERVAL = "24h"
CRON_INTERVAL = None

class CBQuery(object):
    def __init__(self, url, user, password):
        self.cb = CbApi(url, user, password)
        self.cb_url = url

    def report(self, ioc, type, procs):
        for result in procs["results"]:
            # print the results to stdout. you could do anything here - 
            # log to syslog, send a SMS, fire off a siren and strobe light, etc.
            print 
            print "Found %s IOC for %s in:" % (type, ioc)
            print
            print "\tPath: %s"          % procs["results"]["path"]
            print "\tHostname: %s"      % procs["results"]["hostname"]
            print "\tStarted: %s"       % procs["results"]["start"]
            print "\tLast Updated: %s"  % procs["results"]["last_update"]
            print "\tDetails: http://%s/#analyze/%s" % (self.cb_url, procs["results"]["id"])
            print

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
    if len(sys.argv) != 4:
        print "Usage:  check_ioc.py [cb_url] [user] [password]"
        print
        print "Example:"
        print 
        print "[irteam@localhost] python check_ioc.py http://127.0.0.1/ admin test"
        sys.exit(1)

    # setup the CbApi object
    cb_url, user, passwd = sys.argv[1], sys.argv[2], sys.argv[3]
    cb = CBQuery(cb_url, user, passwd)

    # get the IOCs to check; this is a list of strings, one indicator
    # per line.  strip off the newlines as they come in 
    domains = [domain.strip() for domain in open("data/mandiant-domains.txt", "r")]
    md5s = [md5.strip() for md5 in open("data/mandiant-md5s.txt", "r")]

    # check each!
    cb.check(domains, "domain") 
    cb.check(md5s, "md5")

