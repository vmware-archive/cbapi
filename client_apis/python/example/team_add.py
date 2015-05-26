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
        e
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify = opts.ssl_verify)
    
    #checks if the team name is already in use
    team = cb.team_get_team_by_name(opts.team_name)
    if team != None:
        print "Team Name already exists."
        sys.exit(-1)
    
    access_list = opts.group_access_list    
    groups = cb.group_enum()
    
    #checks if there is the right number of groups
    if len(groups) != len(access_list):
        print "There must be the right number of groups in the input"
        sys.exit(-1)
        
    group_access = [1] * len(access_list)
    
    
    for i in range(0,len(access_list)):
        group = groups[i]
        
        numberString = access_list[i]
        
        if numberString == 'a':           
            str = "Administrator"
        elif numberString == 'v':           
            str = "Viewer"
        elif numberString == 'n':
            str = "No Access"
        else:
            print "Only digits 'v','a',and 'n' are valid; Type '-h' for help on the notation"
            sys.exit(-1)
            
        group_access[i] = {\
            'group_id': group['id'],\
            'access_category': str,\
            'group_name': group['name']
        }      
        print group_access[i]
        
        
        
        #cb.add_team_to_group(group,opts.team_name)
        
        
        #sys.exit(-1)        
        
       
        
        # TODO: function: Add team to group's team_access
    
    
    cb.team_add_from_data(opts.team_name,group_access)
   
    ##TODO: Manipulate groups at the same timeformat(,],)
            
    
    results = cb.team_add_from_data(opts.team_name,opts.group_access_list)

    print
    print "-> Team added"  
    print "   -------------------------"
    print "   TeamName  : %s" % (results['teamname'],)
    print
    
    
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))







