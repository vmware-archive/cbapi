import sys
import struct
import socket
import optparse 
sys.path.append('../src/cbapi')


import cbapi 


def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new team to the Carbon Black server")
    
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")    
    parser.add_option("-t", "--teamname", action = "store", default = None, dest = "team_name",
                      help = "Team Name")
    parser.add_option("-g", "--group_acccesses", action = "store", default = None, dest = "group_access_list",
                      help = "List of Group Accesses. 'a' for Administrative access; 'v' for Viewer Access; 'n' for No Access. ie. 'nav' = group_1 no access, group_2 admin access, group_3 view access. See group_enum.py for group rdering")

    return parser

def main(argv):
    
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    
    if not opts.server_url or not opts.token or not opts.team_name or not opts.group_access_list:
        print "Missing required paramaters; Run --help (-h) for information on usage"
        sys.exit(-1)
        
        
        
    # build a cbapi object
    #    
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify = opts.ssl_verify)
    
    #checks if the team name is already in use
    #
    team = cb.team_get_team_by_name(opts.team_name)
    if team != None:
        print "Team Name already exists."
        sys.exit(-1)
    
    access_list = opts.group_access_list    
    groups = cb.group_enum()
    
    #checks if there is the right number of groups
    #
    if len(groups) != len(access_list):
        print "There must be the right number of groups in the input"
        sys.exit(-1)
        
        
        
    #stores the access types for all the groups
    #
    group_access = [1] * len(access_list)
    for i in range(0,len(access_list)):
        group = groups[i]
        letter = access_list[i]
        
        if letter == 'a':           
            str = "Administrator"
        elif letter == 'v':           
            str = "Viewer"
        elif letter == 'n':
            str = "No Access"
        else:
            print "Only letters 'v','a',and 'n' are valid; Type '-h' for help on the notation"
            sys.exit(-1)
            
        group_access[i] = {\
            'group_id': group['id'],\
            'access_category': str,\
            'group_name': group['name']
        }      
        
    #Adds the team
    #
    results = cb.team_add_from_data(opts.team_name,group_access)
   
            
    

    print
    print "-> Team added"  
    print "   -------------------------"
    print "   TeamName  : %s" % (results['name'],)
    print
    
    
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))







