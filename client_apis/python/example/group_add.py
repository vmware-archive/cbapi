import sys
import struct
import socket
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Add a new feed to the Carbon Black server")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-b", "--alert_criticality", action="store", default=1, dest="alert_criticality",
                      help= "Type a number 1-5 for alert criticality")
    parser.add_option("-d", "--banning_enabled", action= "store_true", default=False, dest = "banning_enabled",
                      help= "enable banning")
    parser.add_option("-e", "--collect_cross_procs", action= "store_true", default=False, dest = "collect_cross_procs",
                      help= "collect cross processs events") 
    parser.add_option("-f", "--collect_emet_events", action= "store_true", default=False, dest = "collect_emet_events",
                      help= "Collect EMET events")
    parser.add_option("-g", "--collect_filemods", action= "store_true", default=False, dest = "collect_filemods",
                      help= "Collect File Modifications ")    
    parser.add_option("-i", "--collect_filewritemd5s", action= "store_true", default=False, dest = "collect_filewritemd5s",
                      help= "Collect writing of md5 files ")    
    parser.add_option("-j", "--collect_moduleinfo", action= "store_true", default=False, dest = "collect_moduleinfo",
                      help= "Collect module info")    
    parser.add_option("-k", "--collect moduleloads", action= "store_true", default=False, dest = "collect_moduleloads",
                      help= "Collect binary module (.dll, .sys, .exe) loads")    
    parser.add_option("-l", "--collect_netconns", action= "store_true", default=False, dest = "collect_netconns",
                      help= "Collect network connections")
    parser.add_option("-m", "--collect_nonbinary_filewrites", action= "store_true", default=False, dest = "collect_nonbinary_filewrites",
                     help= "Collect Non-Binary File Writes")    
    parser.add_option("-o", "--collect_processes", action= "store_true", default=False, dest = "collect_processes",
                      help= "Collect Process Information")     
    parser.add_option("-p", "--collect_regmods", action= "store_true", default=False, dest = "collect_regmods",
                      help= "Collect Registry Modifications") 
    parser.add_option("-q", "--collect_storefiles", action= "store_true", default=False, dest = "collect_storefiles",
                      help= "Collect Store Files") 
    parser.add_option("-r", "--collect_usercontext", action= "store_true", default=False, dest = "collect_usercontext",
                      help= "Collect Process user context") 
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
    parser.add_option("-z", "--sensor_exe_name", action= "store", default="null", dest = "sensor_exe_name",
                      help= "Sensor Name")  
    parser.add_option("--aa", "--sensor_version", action= "store", default="Manual", dest = "sensor_version",
                      help= "Sensor Upgrade Policy")    
    parser.add_option("--ab", "--sensorbackend_server", action= "store", default=None, dest = "sensorbackend_server",
                      help= "Server URL")    
    parser.add_option("--ac", "--site_id", action = "store", default = 1, dest = "site_id",
                      help = "Site ID")
    parser.add_option("--ad", "--tamper_level", action= "store", default=0, dest = "tamper_level",
                      help= "Enter 0 or 1 for tamper level (on or off)")    
    parser.add_option("--ae," "--team_access", action = "store", default = [], dest = "team_access",
                      help = "Teams with Access to this group")
    parser.add_option("--af", "--vdi_enabled", action= "store_true", default=False, dest = "vdi_enabled",
                      help= "Enable VDI Behavior")    
    
    
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token: #or not opts.name: #or not opts.sensorbackend_server:
        print "Missing required param; run with --help for usage"
        print "Must include the first two fields with server info and also Sensor Group Name and Server URL"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.server_url, token=opts.token, ssl_verify=opts.ssl_verify)

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
