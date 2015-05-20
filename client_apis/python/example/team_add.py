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

    
    
    return parser

def group_Parser():
    
    print "Insert access"
    
    parser = optparse.OptionParser(usage="%prog [options]", description = "Determines Access type for a group in a Team")
    
    #parser.add_option("-a", "--adminAccess", action = "store_true", dest= "admin_access",
                      #help = "Access to the administration; To disable: -d")
    #parser.add_option("-d", action = "store_false", dest = "admin_access")
    
    #parser.add_option("-v", "--viewerAccess", action = "store_true", dest= "view_access",
                      #help = "View Access; To disable type: -i")
    #parser.add_option("-i", action = "store_false", dest = "view_access")
    
    #parser.add_option("-n", "--noAccess", action = "store_true", dest = "no_access",
                      #help = "No access; to disable type: -n")
    #parser.add_option("-o", action = "store_false", dest = "no_access")
    
    parser.add_option("-t", "--typeAccess", type = "int", dest = "type_of_access",
                      help = "Type of access; 1 for admin, 2 for view, 3 for None")
    
    return parser

def main(argv):
    
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    
    if not opts.server_url or not opts.token or not opts.team_name:
        print "Missing required paramaters; Run --help (-h) for information on usage"
        sys.exit(-1)
    
   
    
        
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    
    
    print cb.sensor(1);
    
    sys.exit(-1)
    
    
    groupsForTeam = cb.group_enum();
    
    groupList = [1] * groupsA.length
    
    
    for num in range(0,groupsA.length):
        parser = group_Parser()
        opts0, args = parser.parse_args(argv)
        
        if opts0.type_of_access != 1 and opts0.type_of_access != 2 and opts0.type_of_access != 3:
            print "Not a valid input; Type -h if you need help when you encounter the parser again"
            sys.exit(-1);
            
        if opts0.type_of_access == 1:
            '''
            Administrator Access
            '''
        elif opts0.type_of_access == 2:
            '''
            Viewer Access
            '''
        elif opts0.type_of_access == 3:
            '''
            No Access
            '''
       
       groupList[num] = opts0.type_of_access
        
        
        
        
        
        
        
        
        
        
        
        
    
    
    
    results = cb.team_add_from_data(opts,team_name)

    print
    print "-> Team added"  
    print "   -------------------------"
    print "   TeamName  : %s" % (results['teamname'],)
    print
    
    
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
