import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Perform a process search")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def output_mostcommon(results, facet_name, legend, max=10):
    """
    output the most common terms from process search facet results
    """

    i = 0
    print "%-60s | %s" % (legend, '% of Total Processes')
    print "%-60s + %s" % ('-' * 60, '-' * 19)
    for entry in results['facets'][facet_name]:
        print "%-60s | %s%%" % (entry['name'], entry['ratio'])
        if i > max:
            break
        else:
            i = i + 1
    print

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # perform a single process search
    #
    processes = cb.process_search("", rows=0)

    print "%-20s : %s" % ('Total Processes', processes['total_results'])
    print "%-20s : %sms" % ('QTime', int(1000*processes['elapsed']))
    print '\n'


    # top-level statistics - 'noisiest' hostnames, processes, parent 
    #   processes, usernames, and full process paths
    #
    output_mostcommon(processes, 'hostname', 'Hostname')
    output_mostcommon(processes, 'process_name', 'Process Name')
    output_mostcommon(processes, 'parent_name', 'Parent Process Name')
    output_mostcommon(processes, 'username_full', 'Username')
    output_mostcommon(processes, 'path_full', 'Full Process Path')

    # deeper-dive - for the noisiest processes, what are the most common
    #   parent process names?
    #
    print
    print "-" * 80
    print

    i = 0
    for entry in processes['facets']['process_name']:
        processes2 = cb.process_search("process_name:%s" % (entry['name'],), rows=0)
        print
        print "Most common parent processes for %s" % (entry['name'],)
        print "-" * 80 
        for entry2 in processes2['facets']['parent_name']:
            try:
                print "  %-40s | %s" % (entry2['name'], entry2['ratio'])
            except:
                pass
        i = i + 1
        if i > 10:
            break

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
