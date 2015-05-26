import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Deletes a group from the Carbon Black server")
    
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-g", "--groupname", action="store", default = None, dest = "group_name",
                      help = "Group Name")
    parser.add_option("-i", "--id", action = "store", default = None, dest = "id_number",
                      help="ID number of the group")
    
    return parser


def main(argv):


    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)    

    if not opts.server_url or not opts.token or (not opts.group_name and not opts.id_number):
        print "Missing required param; run with --help for usage"
        print "Must include the first two fields with server info and also Sensor Group Name and Server URL"
        sys.exit(-1)
        
    
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    
    
    if not opts.id_number:
        group = cb.group_get_group_by_name(opts.group_name)
    else:
        group = cb.group_info(opts.id_number)
        
    if not group:        
        print "-> No configured group with",
        print ("name '%s'" % (opts.group_name)) if not opts.id_number else ("id '%s'" %(opts.id_number)),
        print "found!"
        sys.exit(-1)


    cb.group_del(group['id'])
    
    
    print "-> Group deleted [group=%s]" % (group['name'])
    

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

