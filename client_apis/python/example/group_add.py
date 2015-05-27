import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new group to the Carbon Black server")

    #Access to the Server
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    
    #Setting Tab
    parser.add_option("-m", "--name", action= "store", default=None, dest = "name",
                      help= "Settings: Sensor Group Name")  
    parser.add_option("-s", "--sensorbackend_server", action= "store", default=None, dest = "sensorbackend_server",
                      help= "Settings: Server URL")      
    
    #Advanced Tab
    parser.add_option("--sm", "--sensorside_max_diskusage_m", action = "store", default = 2048, dest = "max_disk_usage_mega",
                      help= "Advanced: Sensor-side Max Disk Usage in MB") #Verify #Verify that its equal
    parser.add_option("--sp", "--sensorside_max_diskusage_p", action = "store", default = 2, dest = "max_disk_usage_per",
                      help= "Advanced: Sensor-side Max Disk Usage in %") #Verify
    parser.add_option("-v", "--vdi_enabled", action= "store_true", default=False, dest = "vdi_enabled",
                      help= "Advanced: Enable VDI Behavior")    
    parser.add_option("--se", "--sensor_exe_name", action= "store", default="", dest = "sensor_exe_name",
                      help= "Advanced: Sensor Name")
    parser.add_option("--sv", "--sensor_version", action= "store", default="Manual", dest = "sensor_version",
                      help= "Advanced: Sensor Upgrade Policy") 
    parser.add_option("-b", "--banning_enabled", action= "store_true", default=False, dest = "banning_enabled",
                      help= "Advanced: enable banning")
    parser.add_option("--tl", "--tamper_level", action= "store_true", default=False, dest = "tamper_level",
                      help= "Advanced: Tamper Level")  
    parser.add_option("--ac", "--alert_criticality", action="store", default=1, dest="alert_criticality",
                      help= "Advanced: Type a number 1-5 for alert criticality")     
    
    #Permissions Tab
    parser.add_option("-t", "--team_access", action = "store", default = None, dest = "team_access",
                      help = "Permissions: List of Group Accesses. 'a' for Administrative access; 'v' for Viewer Access; 'n' for No Access. ie. 'nav' = group_1 no access, group_2 admin access, group_3 view access. See team_enum.py for group ordering")
                      #Verify    
    
    #Event Collection Tab
    parser.add_option("--cpp", "--collect_processes", action= "store_false", default=True, dest = "collect_processes",
                      help= "Collect Process Information")
    parser.add_option("--cfm", "--collect_filemods", action= "store_false", default=True, dest = "collect_filemods",
                      help= "Collect File Modifications ")
    parser.add_option("--crm", "--collect_regmods", action= "store_false", default=True, dest = "collect_regmods",
                      help= "Collect Registry Modifications")  
    parser.add_option("--cml", "--collect_moduleloads", action= "store_false", default=True, dest = "collect_moduleloads",
                      help= "Collect binary module (.dll, .sys, .exe) loads")  
    parser.add_option("--cnc", "--collect_netconns", action= "store_false", default=True, dest = "collect_netconns",
                      help= "Collect network connections")
    parser.add_option("--csf", "--collect_storefiles", action= "store_false", default=True, dest = "collect_storefiles",
                      help= "Collect Store Files")  ##Binaries 
    parser.add_option("--cmi", "--collect_moduleinfo", action= "store_false", default=True, dest = "collect_moduleinfo",
                      help= "Collect module info")  ##Binary Infos 
    parser.add_option("--cuc", "--collect_usercontext", action= "store_false", default=True, dest = "collect_usercontext",
                      help= "Collect Process user context")
    parser.add_option("--cnf", "--collect_nonbinary_filewrites", action= "store_false", default=True, dest = "collect_nonbinary_filewrites",
                      help= "Collect Non-Binary File Writes")      
    parser.add_option("--ccp", "--collect_cross_procs", action= "store_false", default=True, dest = "collect_cross_procs",
                      help= "collect cross process events") 
    parser.add_option("--cee", "--collect_emet_events", action= "store_false", default=True, dest = "collect_emet_events",
                      help= "Collect EMET events")     
    
    #CAN'T FIND IN UI
    #VERIFY THAT THESES ARE ALWAYS THE DEFAULT
    parser.add_option("--sid", "--site_id", action = "store", default = 1, dest = "site_id",
                      help = "Site ID") 
    parser.add_option("--dss", "--datastore_server", action = "store", default=None, dest = "datastore_server",
                      help = "Datastore Server")
    parser.add_option("--max", "--max_licenses", action = "store", default= -1, dest = "max_licenses",
                      help= "Max Licenses") 
    parser.add_option("--md", "--collect_filewritemd5s", action= "store_false", default=True, dest = "collect_filewritemd5s",
                      help= "Collect writing of md5 files ")   


    
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token or not opts.name or not opts.sensorbackend_server:
        print "Missing required param; run with --help for usage"
        print "Must include the first two fields with server info as well as Sensor Group Name and Server URL"
        sys.exit(-1)

    # build a cbapi object
    #    
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)


    teams = cb.team_enum()

    
    #Deals with the case that team_access was not in the input 
    #
    if opts.team_access is None:
        ## Default is all have no access
        access_command = "n"*len(teams)
    else:
        #Verifies that the correct number of inputs for opts.team_access was written down.
        #
        access_command = opts.team_access
        if len(teams) != len(access_command):
            print "%s is not a valid input." %(access_command)
            print "Number of characters must be same as number of teams."
            print "There are %s teams" %(len(teams))
            print "Check 'team_enum.py' to see ordering of teams"            
            sys.exit(-1)        
        
    
    
    #Checks for correct input in alert_criticality
    #
    try:
        alert_number = int(opts.alert_criticality)
    except:
        print "Alert Criticality Level must be an integer"
        sys.exit(-1)
    if alert_number < 1 or alert_number > 5:
        print "Alert Criticality Level must be between 1-5"
    
    
    #Checks correct input for the Max Disk Usage
    #
    try: 
        mdu_Mega = int(opts.max_disk_usage_mega)
        mdu_Perc = int(opts.max_disk_usage_per)
    except:
        print "Max Disk Usage must be an integer"
        sys.exit(-1)
    if mdu_Mega %2:
        mdu_Mega = mdu_Mega + 1
        print "GB quota must be an even number."
        print "Inceasing by 1 to %s MB." % (mdu_Mega)
        
        
    #Conversion of Sensor-side Max Disk Usage in megabytes and percents
    #TODO: Verify        
    if mdu_Mega > 10240 or mdu_Mega < 2:
        print "Max Disk Usage should be greater than 2 MB and less than 10240 MB (10 GB)"
        sys.exit(-1)
    number_conversion = 524288 * mdu_Mega
    if mdu_Perc > 25 or mdu_Perc < 2:
        print "Max Disk Usage percent should be between 2% and 25%"
        sys.exit(-1)
        
    odd = mdu_Perc % 2
    percentA = mdu_Perc/2 + 1 if odd else mdu_Perc/2
    percentB = mdu_Perc/2
    
    
    #Stores the access types for all the groups
    #
    t_Access = [1] * len(access_command)
    for i in range(0,len(t_Access)):
        
        team = teams[i]
        letter = access_command[i]

        if letter == 'a':           
            str = "Administrator"
        elif letter == 'v':           
            str = "Viewer"
        elif letter == 'n':
            str = "No Access"
        else:
            print "Only digits 'v','a',and 'n' are valid; Type '-h' for help on the notation"
            sys.exit(-1)
        t_Access[i] = {\
            'access_category': str,\
            'team_id': team['id'],\
            'team_name': team['name']
        }

    #add the group 
    #
    group = cb.group_add_from_data(opts.alert_criticality, opts.banning_enabled, opts.collect_cross_procs, 
                                     opts.collect_emet_events, opts.collect_filemods, opts.collect_filewritemd5s,
                                     opts.collect_moduleinfo, opts.collect_moduleloads, opts.collect_netconns,
                                     opts.collect_nonbinary_filewrites, opts.collect_processes, opts.collect_regmods,
                                     opts.collect_storefiles, opts.collect_usercontext, opts.datastore_server,
                                     opts.max_licenses, opts.name, number_conversion, percentA,
                                     number_conversion, percentB, opts.sensor_exe_name, 
                                     opts.sensor_version, opts.sensorbackend_server, opts.site_id, opts.tamper_level, 
                                     t_Access, opts.vdi_enabled)

    print "group added."
    for key in group.keys():
        print "%-20s : %s" % (key, group[key])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
