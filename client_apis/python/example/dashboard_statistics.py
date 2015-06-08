__author__ = 'bwolfson'

import sys
import optparse
sys.path.append('../src/cbapi')
import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate the dashboard statistics")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    stats = cb.dashboard_statistics()

    storage = stats['storage']
    server = storage['192.237.206.117']
    for stat_type in server:
        print ""
        print "%s:" % stat_type
        stats = server[stat_type]
        if stat_type == "SqlStoreStats":
            for key in stats.keys():
                if key == "Tables":
                    tables = stats['Tables']
                    for i in range(len(tables)):
                        table = tables[i]
                        print ""
                        print "Table %s:" % i
                        for key in table:
                            print "%-22s : %s" % (key, table[key])

        elif stat_type == "EventStoreStats" or stat_type == "FileSystems":
            dict = stats[0]
            for key in dict.keys():
                print "%-22s : %s" % (key, dict[key])

        else:
            for key in stats.keys():
                print "%-22s : %s" % (key, stats[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
