import sys
import time
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump sensor list")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate")
    parser.add_option("-d", "--details", action="store_true", default=False, dest="detail",
                      help="Show detailed endpoint-by-endpoint listing")
    parser.add_option("-w", "--without-agent", action="store_true", default=False, dest="withoutagent",
                      help="When ouputting detailed report, only output endpoints without an installed platform agent")
    return parser

def cheesy_is_sensor_more_or_less_active(sensor):
    """
    simplistic routine to determine if sensor is active
    make this determination by seeing if the scheduled checkin time is this month
    
    next checkin time is of the form: 2015-03-23 18:09:42.705408-04:00
    """
    ds = sensor['next_checkin_time'].split(' ')[0]
    
    if int(ds.split('-')[0]) < int(time.strftime("%Y")) or \
       int(ds.split('-')[1]) < int(time.strftime("%m")):
        return False
 
    return True 

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # enumerate sensors 
    #
    sensors = cb.sensors()

    num_platform_agents = 0
    num_active_endpoints = 0

    # output each sensor in turn
    #
    if opts.detail:
        print "%-20s | %-40s | %-20s | %s" % ("CB Sensor Id", "Computer Name", "Platform Agent Host Id", "Next Checkin Time")
    
    for sensor in sensors:
        if not cheesy_is_sensor_more_or_less_active(sensor):
            continue
        if opts.detail:
            if not opts.withoutagent or (opts.withoutagent and int(sensor['parity_host_id']) == 0):
                print "%-20s | %-40s | %-20s | %s" % (sensor['id'], sensor['computer_name'], sensor['parity_host_id'], sensor['next_checkin_time'])
        if int(sensor['parity_host_id']) > 0:
            num_platform_agents = num_platform_agents + 1
        num_active_endpoints = num_active_endpoints + 1

    print
    print "Report"
    print "------------"
    print "%-30s : %s" % ("Total Endpoints", num_active_endpoints)
    print "%-30s : %s" % ("Total Platform Agents", num_platform_agents)
    print "%-30s : %s" % ("Percentage w/ Platform Agent", num_platform_agents * 100 / num_active_endpoints)

    if not opts.detail:
        print
        print "Run with the --detail switch for endpoint-by-endpoint reporting"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
