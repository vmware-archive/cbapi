import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display information about an existing team")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-t", "--teamname", action="store", default=None, dest="teamname",
                      help="Team Name")
    parser.add_option("-i", "--teamid", action="store", default=None, dest="teamid",
                      help="Team Id")
    return parser

def output_team_info(team):
    print "%s" % (team['name'])
    print "%s" % ('-' * 80,)
    for key in team.keys():
        if 'group_access' == key:
            print_group_access(team['group_access'])
        elif not 'icon' == key:
            print "%-20s : %s" % (key, team[key])
            
def print_group_access(groups):
    print "Sensor groups this team has access to:"
    for i in range(len(groups)):
        print "%-12s: %-14s | %-10s: %-s " % ("Access Category", groups[i]['access_category'],"Group Name", groups[i]['group_name'])      

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or (not opts.teamname and not opts.teamid):
        print "Missing required param; run with --help for usage"
        print "One of -t or -i must be specified"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    if not opts.teamid:
        team = cb.team_get_team_by_name(opts.teamname)
        if team is None:
            print "-> No configured team with name '%s' found!" % (opts.teamname) 
            sys.exit(-1)
        else:
            id = team['id']
    else:
        id = opts.teamid
        does_exist = False
        for team in cb.team_enum():
            if id == team['id']:
                does_exist = True

        if not does_exist:
            print "-> No configured team with id '%s' found!" % (id)
            sys.exit(-1)
        else:
            output_team_info(cb.team_info(id))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
