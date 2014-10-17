import sys, struct, socket, pprint, argparse, time, datetime, warnings
# in the github repo, cbapi is not in the example directory
# if cbapi.py is local then comment out the sys.path.append statement
sys.path.append('../src/cbapi')
import cbapi

def get_local_time_offset():
    if time.daylight and time.localtime().tm_isdst:
        offsetHour = time.altzone / 3600
        offsetMinute = time.altzone%3600/60
    else:
        offsetHour = time.timezone / 3600
        offsetMinute = time.timezone%3600/60
    return offsetHour, offsetMinute

def sensor_last_checkin_time_to_zulu(last_checkin_time):
    #default lct format: 2014-09-24 14:37:49.899702-07:00
    local_lct = datetime.datetime.strptime(last_checkin_time[:-6], "%Y-%m-%d %H:%M:%S.%f")
    lct_hour_offset = int(last_checkin_time[-5:-3])
    lct_minute_offset = int(last_checkin_time[-2:])
    if last_checkin_time[-6:-5] == '-':
        sensor_zulu_time = local_lct + datetime.timedelta(hours=lct_hour_offset, minutes=lct_minute_offset)
    else:
        sensor_zulu_time = local_lct - datetime.timedelta(hours=lct_hour_offset, minutes=lct_minute_offset)
        
    return sensor_zulu_time

def build_cli_parser():
    parser = argparse.ArgumentParser(description="Prints a list of sensors which have not checked in for longer than a specified number of days or hours.")
    # for each supported output type, add an option
    #
    parser.add_argument("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., https://127.0.0.1 ")
    parser.add_argument("-a", "--apitoken", action="store", default=None, dest="token",
                      help="Carbon Black API Authentication Token")
    parser.add_argument("-s", "--ssl-verify", action="store_true", default=False, dest="ssl_verify",
                      help="SSL Verification. Default = Do not verify")
    parser.add_argument("-d", "--days", action="store", default=0, type=int, dest="max_days", 
                     help="How many days a sensor can be offline before triggering an alert. (Can be used with the hours option)")
    parser.add_argument("-o", "--hours", action="store", default=0, type=int, dest="max_hours", 
                     help="How many hours a sensor can be offline before triggering an alert. (Can be used with the days option)")
    return parser


def main():
    parser = build_cli_parser()
    args = parser.parse_args()
    if not args.url or not args.token:
        print "Missing either server URL or Authentication Token; run with --help for usage"
        sys.exit(-1)
    if args.max_days == 0 and args.max_hours == 0 :
        print "Requires at least one of days or hours parameters; run with --help for usge"
        sys.exit(-1)

    # build a cbapi object
    cb = cbapi.CbApi(args.url, token=args.token, ssl_verify=args.ssl_verify)
    
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # enumerate sensors
        sensors = cb.sensors()

    local_offset = get_local_time_offset()
    local_datetime = datetime.datetime.now()
    zulu_datetime = local_datetime + datetime.timedelta(hours=local_offset[0], minutes=local_offset[1])
    alert_datetime = zulu_datetime - datetime.timedelta(days=args.max_days, hours=args.max_hours)
    
    print "Sensor_id|Hostname|Last_CheckIn_Time"
    for sensor in sensors:
        if not (sensor['uninstalled'] or sensor['status'] == 'Uninstall Pending'):
            sensor_zulu_time = sensor_last_checkin_time_to_zulu(sensor['last_checkin_time'])
            if sensor_zulu_time < alert_datetime:
                print "%s|%s|%s" % (sensor['id'], sensor['computer_name'], sensor['last_checkin_time'] )

if __name__ == "__main__":
    sys.exit(main())

