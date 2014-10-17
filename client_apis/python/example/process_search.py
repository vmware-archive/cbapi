import sys, struct, socket, pprint, argparse, warnings

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = argparse.ArgumentParser(description="Performs a process search. Returns desired fields as a list.", fromfile_prefix_chars='@')

    # for each supported configuration option, add an option
    #
    parser.add_argument("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., https://127.0.0.1 ")
    parser.add_argument("-a", "--apitoken", action="store", default=None, dest="token",
                      help="Carbon Black API Authentication Token")
    parser.add_argument("-n", "--no-ssl-verify", action="store_false", default=False, dest="ssl_verify",
                      help="SSL Verification. Default = Do not verify")
    parser.add_argument("-q", "--query", action="store", default=None, dest="query",
                      help="process query ex. hostname:foo and netconn:45.21.30.115")
    parser.add_argument("-r", "--rows", action="store", default=20, dest="rows", type=int,
                      help="Number of rows to be returned.  Default = 20")
    parser.add_argument("-f", "--fields", action="append", default=[], dest="fields", type=str,
                      help="Field(s) to be returned.  For multiple fields, use this option multiple times.")
    parser.add_argument("-l", "--listfields", action="store_true", default=None, dest="list_fields",
                      help="To get a list of available fields to return, use this flag and do not provide an '-f' argument.")
    return parser

def run_query(args):

    # build a cbapi object
    #
    cb = cbapi.CbApi(args.url, token=args.token, ssl_verify=args.ssl_verify)

    # use the cbapi object to perform a process based search
    #
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        processes = cb.process_search(args.query, rows=args.rows)
    return processes

def main():
    parser = build_cli_parser()
    args = parser.parse_args()
    if not args.url or not args.token or args.query is None:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)
    if not args.fields:
        if args.list_fields:
            args.query=''
            args.rows=1
            processes = run_query(args)
            print "List of fields available to be returned by this script:"
            for process in processes['results']:
                for k in sorted(process.iterkeys()):
                    print k
            sys.exit(0)
        else:
            sys.stderr.write("\nNo fields specified, will return hostname and cmdline fields. For a list of available fields run the script with the '-l' argument.\n\n")
            args.fields.append('hostname')
            args.fields.append('cmdline')
            
    processes = run_query(args)

    # for each result 
    for process in processes['results']:
        fields_to_print = []
        for field in args.fields:
            fields_to_print.append(process[field])
        if fields_to_print:
            print fields_to_print
        
            #Write a warning to stderr so any program that consumes stdout will not have to parse this warning
            if processes['total_results'] > args.rows:
                sys.stderr.write( "Warning: Query returned %s total result(s), but only displaying %s result(s).\n" % (processes['total_results'], args.rows))

if __name__ == "__main__":
    sys.exit(main())

