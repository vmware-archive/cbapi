import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    
    parser = optparse.OptionParser(usage="%prog [options]", description="Delete an existing team")

    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")    
    parser.add_option("-t", "--teamname", action = "store", default = None, dest = "teamname", help = "Feed Team Name")
    parser.add_option("-i", "--id", action="store", default=None, dest="teamid",
                      help="Team Id") 
    
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)

    if not opts.server_url or not opts.token or (not opts.teamname and not opts.teamid):
        print "Missing required param; run with --help for usage"
        print "One of -t or -i must be specified"
        sys.exit(-1)
    
    
    # build a cbapi object
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    if not opts.teamid:
        id = cb.team_get_id_by_name(opts.teamname)
        if id is None:
            print "-> No team found with team name: %s" % (opts.teamname)
        
    else:
        id = opts.teamid
        if cb.team_del(id) is None:
            print "->No team found with team id: %s" %(opts.teamid) 
        
    # delete the team
    team = cb.team_get_team_by_id(id)
    cb.team_del(id)    
    
    print "-> Team deleted [team=%s]" % (team['name'])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))    