import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Display information about an existing group")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-g", "--groupname", action="store", default=None, dest="groupname",
                      help="Group Name - use quotes")
    parser.add_option("-i", "--groupid", action="store", default=None, dest="groupid",
                      help="Group Id")
    return parser

def output_group_info(group):
    print "%s" % (group['name'])
    print "%s" % ('-' * 80,)
    for key in group.keys():
        if 'team_access' == key:
            print_team_access(group['team_access'])
        elif not 'icon' == key:
            print "%-20s : %s" % (key, group[key])
            
def print_team_access(team_access):
    for team in team_access:
        print "%-12s: %-14s | %-10s: %-s " % ("Access Category", team['access_category'],"Team Name", team['team_name'])    

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or (not opts.groupname and not opts.groupid):
        print "Missing required param; run with --help for usage"
        print "One of -g or -i must be specified"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

    if not opts.groupid:
        id = cb.group_get_id_by_name(opts.groupname)
        if id  is None:
            print "-> No configured group with name '%s' found!" % (opts.groupname)
            sys.exit(-1)
    else:
        id = opts.groupid
        if cb.group_info(id) is None:
            print "-> No configured group with id '%s' found!" % (opts.groupid)
            sys.exit(-1)

    #Verifies that the id and the groupname matches
    if opts.groupid and opts.groupname:
        group1 = cb.group_get_group_by_name()
        group2 = cb.group_info(id)
        if group1 != group2:
            print "The Group ID and the Group Name don't correspond to the same group."
            print "Check group_enum.py to make sure the name and id correspond to the same group."
            sys.exit(-1)


    group = cb.group_info(id)
    output_group_info(group)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))