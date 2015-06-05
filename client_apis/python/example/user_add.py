import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 


def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new user to the Carbon Black server")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default = True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-u", "--username", action="store", default=None, dest="username")
    parser.add_option("-f", "--first_name", action="store", default=None, dest="first_name",
                      help="First Name of the user")
    parser.add_option("-l", "--last_name", action="store", default=None, dest="last_name",
                      help="Last Name of the user")
    parser.add_option("-p", "--password", action="store", default=None, dest="password",
                      help="Password for user") 
    parser.add_option("-q", "--confirm_password", action="store", default=None, dest="confirm_password",
                      help="Confirm the password")         
    parser.add_option("-g", "--global_admin", action="store_true", default= False, dest="global_admin",
                      help="Assign user as global administrator")
    parser.add_option("-e", "--email", action="store", default= None, dest="email",
                      help="Email address of the user")
    parser.add_option("-t", "--on_teams", action = "store", default = [], dest = "on_teams",
                      help= "type a string of yes (y) and no (n) for whether or not this user should be assigned to each team, i.e. yny means user is on teams 1 and 3")
    
    return parser
    



def main(argv):
    
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    
    if not opts.server_url or not opts.token or not opts.username or not opts.first_name or not opts.last_name or not opts.password or not opts.confirm_password or not opts.email:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)
        
    if not opts.password == opts.confirm_password:
        print "passwords did not match"
        sys.exit(-1)
        
    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)
    
    #checks if username is already in use
    user = cb.user_info(opts.username)
    if user != None:
        print "Username in use"
        sys.exit(-1)
        
    on_teams = opts.on_teams #input string from the user i.e ynnyy    
    curr_teams = cb.team_enum()
            
    #checks if there is the right number of teams
    if len(on_teams) != len(curr_teams):
        print "There must be the right number of teams in the input"
        sys.exit(-1)
                
    teams = []
    for i in range(0,len(on_teams)):
        
        team = curr_teams[i] #the current team in existence
                
        choice = on_teams[i] #whether or not the user is on that team (y or n)
                
        if choice == 'y':           
            teams.append(team)
        elif choice == 'n':           
            continue
        else:
            print "Only digits 'y' and 'n' are allowed; Type '-h' for help on the notation"
            sys.exit(-1)   

     
    # add user to the UI
    cb.user_add_from_data(opts.username, opts.first_name, opts.last_name, opts.password, opts.confirm_password, opts.global_admin, teams, opts.email)


    print "-> User added"  
    print "   -------------------------"
    print "   username     : %s" % (results['username'],)
    print "   First Name  : %s" % (results['first_name'],)
    print "   Last Name  : %s" % (results['last_name'],)
    print "   Password  : %s" % (results['password'])
    print "   Global Administrator  : %s" % (results['global_admin'],)
    print "   Teams  : %s" % (results['teams'],)
    print "   Email Address  : %s" % (results['email'],)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
