import sys
import struct
import socket
import pprint
import optparse 


# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display information about a user")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-u", "--username", action="store", default=None, dest="username",
                      help="username")
    parser.add_option("-f", "--firstname", action="store", default=None, dest="first_name",
                      help="first name")
    parser.add_option("-l", "--lastname", action="store", default=None, dest="last_name",
                      help="last name")    
    return parser

def output_user_info(user):
    
    print "%-20s %s" % (user['first_name'], user['last_name'])
    print "%s" % ('-' * 80,)
    print "%-20s : %s" % ("username", user['username'])
    print "%-20s : %s" % ("User First Name", user['first_name'])
    print "%-20s : %s" % ("User Last Name", user['last_name'])
    print "%-20s : %s" % ("Global Admin?", user['global_admin'])
    print "%-20s : %s" % ("Number of Teams", len(user['teams']))
    teams = user['teams']
    if len(teams) > 0:
        print "%-20s : %s" % ("Teams", teams[0]['name'])
        for i in range(len(teams)-1): 
            print "%-20s : %s" % ("", teams[i+1]['name'])
    print "%-20s : %s" % ("User Email Address", user['email'])
	

def main(argv):
 
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or (not opts.username and (not opts.first_name or not opts.last_name)) :
        print "Missing required param; run with --help for usage"
        print "Either username must be satisfied -u or first and last name must be satisfied -f and -l"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

  #  import pdb; pdb.set_trace()
	
    if not opts.username:
        user = cb.user_get_user_by_name(opts.first_name, opts.last_name)
        if user is None:
            print "-> No configured user with name '%s %s' found!" % (opts.first_name, opts.last_name) 
            sys.exit(-1)
        else:
             username = user['username']
    else:
        username = opts.username
        #Check if the username exists
        does_exist = False

        for user in cb.user_enum():
            if username == user['username']:
                does_exist = True

        if does_exist:
            user = cb.user_info(username)
            output_user_info(user)
        else:
            print "-> No configured user with username '%s' found!" % (opts.username)
            sys.exit(-1)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
