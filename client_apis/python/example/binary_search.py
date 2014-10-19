import sys, struct, socket, pprint, argparse, warnings

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = argparse.ArgumentParser(description="Perform a binary search")

    # for each supported output type, add an argument
    #
    parser.add_argument("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., https://127.0.0.1 ")
    parser.add_argument("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_argument("-n", "--no-ssl-verify", action="store_false", default=False, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_argument("-q", "--query", action="store", default=None, dest="query",
                      help="binary query")
    parser.add_argument("-r", "--rows", action="store", default=20, dest="rows", type=int,
                      help="Number of rows to be returned.  Default = 20")
    parser.add_argument("-f", "--fields", action="append", default=[], dest="fields", type=str,
                      help="Field(s) to be returned.  For multiple fields, use this option multiple times.")
    parser.add_argument("-l", "--listfields", action="store_true", default=None, dest="list_fields",
                      help="To get a list of available fields to return, use this flag and do not provide an '-f' argument.")
    return parser

def main():
    parser = build_cli_parser()
    opts, args = parser.parse_args()
    if not opts.url or not opts.token or opts.query is None:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # perform a single binary search
    #
    binaries = cb.binary_search(opts.query)
    
    print "%-20s : %s" % ('Displayed Results', len(binaries['results']))
    print "%-20s : %s" % ('Total Results', binaries['total_results'])
    print "%-20s : %sms" % ('QTime', int(1000*binaries['elapsed']))
    print '\n'

    # for each result 
    for binary in binaries['results']:
        print binary['md5']
        print "-" * 80
        print "%-20s : %s" % ('Size (bytes)', binary.get('orig_mod_len', '<UNKNOWN>'))
        print "%-20s : %s" % ('Signature Status', binary.get('digsig_result', '<UNKNOWN>'))
        print "%-20s : %s" % ('Publisher', binary.get('digsig_publisher', '<UNKNOWN>'))
        print "%-20s : %s" % ('Product Version', binary.get('product_version', '<UNKNOWN>'))
        print "%-20s : %s" % ('File Version', binary.get('file_version', '<UNKNOWN'))
        print "%-20s : %s" % ('64-bit (x64)', binary.get('is_64bit', '<UNKNOWN>'))
        print "%-20s : %s" % ('EXE', binary.get('is_executable_image', '<UNKNOWN>'))
 
        if len(binary.get('observed_filename', [])) > 0:
            print "%-20s : %s" % ('On-Disk Filename(s)', binary['observed_filename'][0].split('\\')[-1])
            for observed_filename in binary['observed_filename'][1:]:
                print "%-20s : %s" % ('', observed_filename.split('\\')[-1])

        print '\n'
if __name__ == "__main__":
    sys.exit(main())
