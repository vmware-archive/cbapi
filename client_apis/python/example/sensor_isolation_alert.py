#!/bin/env python
# A script to send an email for any Carbon Black sensors that have changed 
#  the state of their network isolation since the last running of this script.
# Run this script via a job scheduler, such as cron, to be notified 
#  when a sensor's network isolation state has changed.
# The script will track isolated sensors between runs via isolated_sensors.txt

__author__ = 'BJSwope'
import sys
import optparse
import warnings
import smtplib
import cbapi
import json
import collections
import socket
from email.mime.text import MIMEText

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump sensor list")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store", default=False, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-g", "--group", action="store", default=None, dest="groupid",
                      help="Limit sensor listing to just those specified by the sensor group id provided")
    parser.add_option("-f", "--mailfrom", action="store", default=None, dest="mailfrom",
                    help="Email from address.")
    parser.add_option("-t", "--rcptto", action="store", default="bj@carbonblack.com", dest="rcptto",
                    help="Email recipient.")
    parser.add_option("-m", "--mailserver", action="store", default="localhost", dest="mailserver",
                    help="Mail server to route email.")
    return parser


def send_mail(sensor,opts):
    mail = {}
    if sensor['network_isolation_enabled'] == True: 
        if sensor['is_isolating'] == True:
            # Isolation Enabled and Active email
            msg="Network Isolation enabled and active!\r\n Host: %s\r\nCarbon Black Console: %s\r\n Last Check-In Time: %s\r\n" \
            % (sensor['computer_name'], sensor['url'], sensor['last_checkin_time'])
            msg = MIMEText(msg)
            msg['Subject'] = 'Host Isolation Activated By Carbon Black'
        else:
            # Isolation Enabled but Not Active email
            msg="Network Isolation enabled and will activate at next sensor check in.\r\n Host: %s\r\nCarbon Black Console: %s\r\n Last Check-In Time: %s\r\nNext Check-In Time: %s" \
            % (sensor['computer_name'], sensor['url'], sensor['last_checkin_time'], sensor['next_checkin_time'])
            msg = MIMEText(msg)
            msg['Subject'] = 'Host Isolation Enabled By Carbon Black'
    elif sensor['network_isolation_enabled'] == False:
        # Isolation Disabled email
        msg="Network Isolation disabled and will deactivate at next sensor check in.\r\n Host: %s\r\nCarbon Black Console: %s\r\n Last Check-In Time: %s\r\nNext Check-In Time: %s" \
            % (sensor['computer_name'], sensor['url'], sensor['last_checkin_time'], sensor['next_checkin_time'])
        msg = MIMEText(msg)
        msg['Subject'] = 'Host Isolation Disabled By Carbon Black'
    else:
        return
    if opts.mailfrom == None:
        hostname = socket.getfqdn()
        opts.mailfrom = 'sensor_isolation@%s' % (hostname)

    msg['From'] = opts.mailfrom
    msg['To'] = opts.rcptto
    
    s = smtplib.SMTP(opts.mailserver)
    s.sendmail(msg['From'], msg['To'], msg.as_string())
    s.quit()

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sensors = cb.sensors()
   
    f = open("isolated_sensors.txt", "w+")
    fis = f.read()
    f.close()

    try:
        former_iso_sensors = json.loads(fis)
    except ValueError:
        former_iso_sensors = collections.defaultdict(dict)
    
    current_iso_sensors = collections.defaultdict(dict)

    for sensor in sensors:
        if sensor['network_isolation_enabled'] == True:
            #sensor should be isolating, add sensor to list of currently iso enabled sensors
            sid = str(sensor['id'])
            sensor['url'] = opts.url + "/#/host/" + sid
            current_iso_sensors[sid]['network_isolation_enabled'] = sensor['network_isolation_enabled']
            current_iso_sensors[sid]['is_isolating'] =  sensor['is_isolating']
            try:
                if not sensor['is_isolating'] == former_iso_sensors[sid]['is_isolating']:
                    #state change, send email
                    send_mail(sensor,opts)
            except KeyError  as e:
                #sid is not present in former_iso_sensors, new sensor isolation, send email
                send_mail(sensor,opts)

    f = open("isolated_sensors.txt", "w")
    f.write(json.dumps(current_iso_sensors))
    f.close()
    
    #remove current isolations from from former isolations leaving the list of sensors removed from
    # isolation since the last running of this script
    iso_removed = [item for item in former_iso_sensors if item not in current_iso_sensors]
    for fixed in iso_removed:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sensor = cb.sensor(fixed)
        sid = str(sensor['id'])
        sensor['url'] = opts.url + "/#/host/" + sid
        #send notification of isolation removal
        send_mail(sensor,opts)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

""" List of fields that can be included in the emails as of CB Version 5.1.1 p1:
boot_id
build_id
build_version_string
clock_delta
computer_dns_name
computer_name
computer_sid
cookie
display
emet_dump_flags
emet_exploit_action
emet_is_gpo
emet_process_count
emet_report_setting
emet_telemetry_path
emet_version
event_log_flush_time
group_id
id
is_isolating
last_checkin_time
last_update
license_expiration
network_adapters
network_isolation_enabled
next_checkin_time
node_id
notes
num_eventlog_bytes
num_storefiles_bytes
os_environment_display_string
os_environment_id
os_type
parity_host_id
physical_memory_size
power_state
registration_time
restart_queued
sensor_health_message
sensor_health_status
sensor_uptime
shard_id
status
supports_2nd_gen_modloads
supports_cblr
supports_isolation
systemvolume_free_size
systemvolume_total_size
uninstall
uninstalled
uptime
"""
