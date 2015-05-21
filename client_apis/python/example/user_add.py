import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

team_enrollment = []

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
    
    return parser
    
def build_cli_parser2(cb):
    
    print cb.team_enum()
    parser2 = optparse.OptionParser(usage="%prog [options]", description="Add a new user to the Carbon Black server")
    for team in cb.team_enum():
        on_team = "team_%s" % (team['team_name'])
        parser2.add_option("-n", "--team_%s", action="store_true", default = False, dest = on_team,
                          help = "Will this user be on %s? Include -n if so") % (team['team_name'])
        if opts.on_team:
            team_enrollment.append(True)
        else:
            team_enrollment.append(False)
            
    return parser2

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
    
    parser2 = build_cli_parser2(cb)
    opts, args = parser2.parse_args(argv)
    
    user_teams = []
    curr_teams = cb.team_enum()
    for i in range(curr_teams.length()):
        if team_enrollment[i] == True:
            user_teams.append(curr_teams[i])
    
     
    # add user to the UI
    results = cb.user_add_from_data(opts.username, opts.first_name, opts.last_name, opts.password, opts.confirm_password, opts.global_admin, user_teams, opts.email)

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
