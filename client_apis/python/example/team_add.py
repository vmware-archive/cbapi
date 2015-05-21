import sys
import struct
import socket
import optparse 
sys.path.append('../src/cbapi')


import cbapi 


def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new feed to the Carbon Black server")
    
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")    
    parser.add_option("-t", "--teamname", action = "store", default = None, dest = "team_name",
                      help = "Team Name")
    parser.add_option("-g", "--group_acccesses", action = "store", default = None, dest = "group_access_list",
                      help = "List of Group Accesses")

    
    
    return parser

def main(argv):
    
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    
    if not opts.server_url or not opts.token or not opts.team_name or not opts.group_access_list:
        print "Missing required paramaters; Run --help (-h) for information on usage"
        sys.exit(-1)
    
   
    
        
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify = opts.ssl_verify)
    
    #checks if the team name is already in use
    team = cb.team_get_teamname(opts.team_name)
    if team != None:
        print "Team Name already exists."
        sys.exit(-1)
    
    
    
    ##TODO: Manipulate groups at the same time
    
    

    
    results = cb.team_add_from_data(opts,team_name)

    print
    print "-> Team added"  
    print "   -------------------------"
    print "   TeamName  : %s" % (results['teamname'],)
    print
    
    
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
