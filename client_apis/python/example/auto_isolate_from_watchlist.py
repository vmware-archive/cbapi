#!/usr/bin/env python
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------
#
#  2016-02-10 by Jon Ross jross@carbonblack.com
#    Based on auto_blacklist_from_watchlist.py 2015-10-23 
#    by Jason McFarland jmcfarland@bit9.com
#


import pika
import random
import json
import requests
import sys
from ConfigParser import SafeConfigParser
import cbapi

def isolate_sensor(sensor):
    global cbtoken
    global cbserver

    print "Isolating sensor %s on %s..." % (sensor, cbserver)

    cbURL = "https://" + cbserver
    cb = cbapi.CbApi(cbURL, token=cbtoken, ssl_verify=False)
    status = cb.sensor_toggle_isolation(sensor,True)

    print "status was %s" % status

def on_message(channel, method_frame, header_frame, body):
    """
    Callback function which filters out the feeds we care about.
    """

    try:
        if "application/json" == header_frame.content_type:

            if method_frame.routing_key == 'watchlist.hit.binary':
                print "watchlist.hit.binary consume"

                parsed_json = json.loads(body)
                if parsed_json['watchlist_id'] in watchlistsdict.values():
                    lst = parsed_json['docs']
                    for item in lst:
                        isolate_sensor(parsed_json['docs'][0]['sensor_id'])

            elif method_frame.routing_key == 'watchlist.hit.process':
                print "watchlist.hit.process consume"

                parsed_json = json.loads(body)
                #print parsed_json['docs'][0]['sensor_id']
                if parsed_json['watchlist_id'] in watchlistsdict.values():
                    lst = parsed_json['docs']
                    for item in lst:
                        isolate_sensor(parsed_json['docs'][0]['sensor_id'])

    except Exception, e:
        print e
    finally:
        # need to make sure we ack the messages so they don't get left un-acked
        # in the queue we set multiple to true to ensure that we ack all
        # previous messages
        channel.basic_ack(delivery_tag=method_frame.delivery_tag,
                          multiple=True)
    return


def generate_queue_name():
    """
    generates a random queue name
    """
    return str(random.randint(0, 10000)) + "-" + str(random.randint(0, 100000))


def parse_config_file(filename):
    """
    Parses the config file passed into this script
    NOTE: note the conversion to unicode
    """

    parser = SafeConfigParser()
    parser.read(filename)

    return (unicode(parser.get("settings", "rabbitmqusername"), "utf-8"),
            unicode(parser.get("settings", "rabbitmqpassword"), "utf-8"),
            unicode(parser.get("settings", "cbserverip"), "utf-8"),
            unicode(parser.get("settings", "cbtoken"), "utf-8"),
            unicode(parser.get("settings", "watchlists"), "utf-8"))


def validate_watchlist_dict(watchlistsdict):
    """
    Validates the watchlist dictionary and watchlist names with no
    associated ID will warn the user that the ID could not be found.
    This means that auto-blacklisting will not trigger since this script
    could not find the blacklist on the specified Carbon Black Server
    """

    for key, value in watchlistsdict.iteritems():
        if not value:
            print "Warning: ID for watchlist %s not found." % (key)
        else:
            print "Watchlist: %s, ID: %d" % (key, value)

def get_watchlist_id_by_name(watchlistsdict):
    """
    For each watchlist name specified in the config file, find the
    associated watchlist ID.
    NOTE: We trigger on watchlist IDs, and not on watchlist names
    """
    global cbtoken
    global cbserver

    headers = {'X-AUTH-TOKEN': cbtoken}

    r = requests.get("https://%s/api/v1/watchlist" % (cbserver),
                      headers=headers,
                      verify=False)

    parsed_json = json.loads(r.text)

    for watchlist in parsed_json:
        for key, value in watchlistsdict.iteritems():
            if watchlist['name'].lower() == key.lower():
                watchlistsdict[key] = watchlist['id']

def Usage():
    return ("Usage: python auto_blacklist_from_watchlist.py <config file>")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print Usage()
        exit(0)

    configfile = sys.argv[1]

    global cbtoken
    global watchlistsdict
    global cbserver

    #
    # Parse the config file
    #
    (username, password, cbserver, cbtoken, watchlists) = parse_config_file(configfile)

    #
    # Build a dictionary of "WatchList Name" -> "Watchlist ID"
    #
    watchlistsdict = dict.fromkeys([watchlist.strip() for watchlist in watchlists.split(',')])

    #
    # Populate the values of the dictionary with the watchlist ID.
    # This function will query the Carbon Black server and find the 
    # associated ID
    #
    get_watchlist_id_by_name(watchlistsdict)

    #
    # Validate that all the watchlist names have associated IDs.
    # If a name does not have an associated ID then we just warn the user.
    #
    validate_watchlist_dict(watchlistsdict)

    #
    # Set the connection parameters to connect to to the rabbitmq:5004
    # using the supplied username and password
    #
    credentials = pika.PlainCredentials(username,
                                        password)

    #
    # Create our parameters for pika
    #
    parameters = pika.ConnectionParameters(cbserver,
                                           5004,
                                           '/',
                                           credentials)

    #
    # Create the connection
    #
    connection = pika.BlockingConnection(parameters)

    #
    # Get the channel from the connection
    #
    channel = connection.channel()

    #
    # Create a random queue name
    #
    queue_name = generate_queue_name()

    #
    # make sure you use auto_delete so the queue isn't left filling
    # with events when this program exists.
    channel.queue_declare(queue=queue_name, auto_delete=True)

    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='watchlist.hit.#')

    channel.basic_consume(on_message, queue=queue_name)

    print
    print "Subscribed to events!"
    print ("Keep this script running to auto-blacklist md5 hashes "
           "from watchlist.hit.process and watchlist.hit.binary hits!")
    print

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()

    connection.close()
