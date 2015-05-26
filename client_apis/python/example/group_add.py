import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new group to the Carbon Black server")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    
    
    
    
    
    
    parser.add_option("-b", "--alert_criticality", action="store", default=1, dest="alert_criticality",
                      help= "Type a number 1-5 for alert criticality") #DONE
    parser.add_option("-d", "--banning_enabled", action= "store_true", default=False, dest = "banning_enabled",
                      help= "enable banning") #DONE
    parser.add_option("-e", "--collect_cross_procs", action= "store_false", default=True, dest = "collect_cross_procs",
                      help= "collect cross processs events") #DONE
    parser.add_option("-f", "--collect_emet_events", action= "store_false", default=True, dest = "collect_emet_events",
                      help= "Collect EMET events") #DONE
    parser.add_option("-g", "--collect_filemods", action= "store_false", default=True, dest = "collect_filemods",
                      help= "Collect File Modifications ")    #DONE
    parser.add_option("-i", "--collect_filewritemd5s", action= "store_true", default=True, dest = "collect_filewritemd5s",
                      help= "Collect writing of md5 files ")    
    parser.add_option("-j", "--collect_moduleinfo", action= "store_false", default=True, dest = "collect_moduleinfo",
                      help= "Collect module info")    #DONE
    parser.add_option("-k", "--collect_moduleloads", action= "store_false", default=True, dest = "collect_moduleloads",
                      help= "Collect binary module (.dll, .sys, .exe) loads")  #DONE  
    parser.add_option("-l", "--collect_netconns", action= "store_false", default=True, dest = "collect_netconns",
                      help= "Collect network connections") #DONE
    parser.add_option("-m", "--collect_nonbinary_filewrites", action= "store_false", default=True, dest = "collect_nonbinary_filewrites",
                     help= "Collect Non-Binary File Writes")    #DONE
    parser.add_option("-o", "--collect_processes", action= "store_false", default=True, dest = "collect_processes",
                      help= "Collect Process Information")     #DONE
    parser.add_option("-p", "--collect_regmods", action= "store_false", default=True, dest = "collect_regmods",
                      help= "Collect Registry Modifications") #DONE
    parser.add_option("-q", "--collect_storefiles", action= "store_false", default=True, dest = "collect_storefiles",
                      help= "Collect Store Files") #DONE
    parser.add_option("-r", "--collect_usercontext", action= "store_false", default=True, dest = "collect_usercontext",
                      help= "Collect Process user context") #DONE
    parser.add_option("-s", "--datastore_server", action = "store", default=None, dest = "datastore_server",
                      help = "Datastore Server")
    parser.add_option("-t", "--name", action= "store", default=None, dest = "name",
                      help= "Sensor Group Name")      
    parser.add_option("-u", "--max_licenses", action = "store", default= -1, dest = "max_licenses",
                      help= "Max Licenses") 
    parser.add_option("-v", "--quota_eventlog_bytes", action = "store", default = 1073741824, dest = "quota_eventlog_bytes",
                      help = "Quota Eventlog Bytes")
    parser.add_option("-w", "--quota_eventlog_percent", action = "store", default = 1, dest = "quota_eventlog_percent",
                      help = "Quota Eventlog Percent")
    parser.add_option("-x", "--quota_storefile_bytes", action = "store", default = 1073741824, dest = "quota_storefile_bytes",
                      help = "Quota Storefile Bytes")
    parser.add_option("-y", "--quota_storefile_percent", action = "store", default = 1, dest = "quota_storefile_percent",
                      help = "Quota Storefile Percent")
    parser.add_option("-z", "--sensor_exe_name", action= "store", default="", dest = "sensor_exe_name",
                      help= "Sensor Name")  #DONE
    parser.add_option("--aa", "--sensor_version", action= "store", default="Manual", dest = "sensor_version",
                      help= "Sensor Upgrade Policy")    #DONE
    parser.add_option("--ab", "--sensorbackend_server", action= "store", default=None, dest = "sensorbackend_server",
                      help= "Server URL")    
    parser.add_option("--ac", "--site_id", action = "store", default = 1, dest = "site_id",
                      help = "Site ID") #DONE
    parser.add_option("--ad", "--tamper_level", action= "store_true", default=False, dest = "tamper_level",
                      help= "Tamper Level") #DONE    
    parser.add_option("--ae," "--team_access", action = "store", default = [], dest = "team_access",
                      help = "List of Group Accesses. 'a' for Administrative access; 'v' for Viewer Access; 'n' for No Access. ie. 'nav' = group_1 no access, group_2 admin access, group_3 view access. See team_enum.py for group ordering") 
    parser.add_option("--af", "--vdi_enabled", action= "store_true", default=False, dest = "vdi_enabled",
                      help= "Enable VDI Behavior")    #DONE
    
    
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
        print "Missing required param; run with --help for usage"
        print "Must include the first two fields with server info as well as Sensor Group Name and Server URL"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)



    
    #stores the access types for all the groups
    #
    
    teams = cb.team_enum()
    
    #Verifies that the correct number of inputs for opts.team_access was written down.
    #
    if len(team) != len(opts.team_access):
        print "Number of characters in the team_access must be same as number of teams. Check 'team_enum.py' to see the number of teams"
        sys.exit(-1)
    
    team_access = [1] * len(opts.team_access)
    print len(opts.team_access)
    for i in range(0,len(team_access)):
        team = teams[i]
        letter = opts.team_access[i]

        if letter == 'a':           
            str = "Administrator"
        elif letter == 'v':           
            str = "Viewer"
        elif letter == 'n':
            str = "No Access"
        else:
            print "Only digits 'v','a',and 'n' are valid; Type '-h' for help on the notation"
            sys.exit(-1)


        print str
        team_access[i] = {\
            'access_category': str,\
            'team_id': group['id'],\
            'team_name': group['name']
        }
        
        sys.exit(-1)


    #add the group 
    #
    group = cb.group_add_from_data(opts.alert_criticality, opts.banning_enabled, opts.collect_cross_procs, 
                                     opts.collect_emet_events, opts.collect_filemods, opts.collect_filewritemd5s,
                                     opts.collect_moduleinfo, opts.collect_moduleloads, opts.collect_netconns,
                                     opts.collect_nonbinary_filewrites, opts.collect_processes, opts.collect_regmods,
                                     opts.collect_storefiles, opts.collect_usercontext, opts.datastore_server,
                                     opts.max_licenses, opts.name, opts.quota_eventlog_bytes, opts.quota_eventlog_percent,
                                     opts.quota_storefile_bytes, opts.quota_storefile_percent, opts.sensor_exe_name, 
                                     opts.sensor_version, opts.sensorbackend_server, opts.site_id, opts.tamper_level, 
                                     opts.team_access, opts.vdi_enabled)

    print "group added."
    for key in group.keys():
        print "%-20s : %s" % (key, group[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
