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
#  last updated 2016-03-11 by Jon Ross jross@carbonblack.com
#   Generic parsing from config file for all decision logic implemented.
#  2016-02-07 by Jon Ross jross@carbonblack.com
#   Trigger on ingress messages for RSA demo.  Might need to make it more 
#   generic and parse queries later.
#  2015-10-23 by Jason McFarland jmcfarland@bit9.com
#


import pika
import random
import json
import requests
import sys
from ConfigParser import SafeConfigParser
import event_helpers as pbuf
import re
import time
from datetime import datetime
import cbapi
import bit9api

def check_triggers(message):
    global action_triggers
    return_value = False
    target_policy = ""

    for policy in action_triggers:
#       Need to make a copy here cause globals :(
        rules = list(action_triggers[policy]['rules'])
        while rules:
            criteria = rules.pop(0)
            expression = rules.pop(0)
            if re.search(expression, message[criteria].lower()):
                return_value = True
            else:
                return_value = False
                rules = []
        
        if return_value:
            target_policy = action_triggers[policy]['targetpolicy']
            break

    return return_value,target_policy

def move_policy(sensor, targetPolicy):
    global eptoken
    global epserver

    bit9 = bit9api.bit9Api(
        "https://"+epserver,  # Replace with actual Bit9 server URL
        token=eptoken,
        ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
    )
    
    # policy to send the naughty host to
    targetPolicyName = targetPolicy
    destPolicies = bit9.search('v1/policy', ['name:'+targetPolicyName])
    if len(destPolicies)==0:
        raise ValueError("Cannot find destination policy "+targetPolicyName)

    # find the computer id
    destComputer = bit9.search('v1/computer', ['cbSensorId:'+str(sensor)])
    if len(destComputer)==0:
      raise ValueError("Cannot find computer named "+hostname)

    for c in destComputer:
      print "Moving computer %s from policy %s to policy %s" % (c['name'], c['policyName'], targetPolicyName)
      c['policyId'] = destPolicies[0]['id']
      bit9.update('v1/computer', c)
 
def on_message(channel, method_frame, header_frame, body):
    """
    Callback function which filters out the feeds we care about.
    """
    global cbserver
    global cbtoken

    try:
        if "application/protobuf" == header_frame.content_type:
            if method_frame. routing_key == 'ingress.event.process':
                (sensor, message)  = pbuf.protobuf_to_obj_and_host(body)
#                if re.search('powershell.exe$',message['path']) and re.search("iex.+?downloadstring\('http", message['command_line'].lower()):
#                  move_policy(sensor)
#                  print "ingress.event.process consume"
                (hit,policy) = check_triggers(message)
		if hit:
                  move_policy(sensor,policy)
                  print "ingress.event.process consume"
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

    triggers={}
    parser = SafeConfigParser()
    parser.read(filename)

    for s in parser.sections():
      if s != 'settings':
        triggers[s]={}
        triggers[s]['rules']=[]
        for o in parser.options(s):
          stuff = o.lstrip("regex_")
          if stuff != o:
            triggers[s]['rules'].append(stuff)
            triggers[s]['rules'].append(unicode(parser.get(s,o), "utf-8"))
          else:
            triggers[s][o]=unicode(parser.get(s,o), "utf-8").strip("'")

    return (unicode(parser.get("settings", "rabbitmqusername"), "utf-8"),
            unicode(parser.get("settings", "rabbitmqpassword"), "utf-8"),
            unicode(parser.get("settings", "cbserverip"), "utf-8"),
            unicode(parser.get("settings", "cbtoken"), "utf-8"),
            unicode(parser.get("settings", "epserverip"), "utf-8"),
            unicode(parser.get("settings", "eptoken"), "utf-8"),
            triggers)

def Usage():
    return ("Usage: python move_policy_from_mbus.py <config file>")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print Usage()
        exit(0)

    configfile = sys.argv[1]

    global cbtoken
    global cbserver
    global eptoken
    global epserver
    global action_triggers
    #
    # Parse the config file
    #
    (username, password, cbserver, cbtoken, epserver, eptoken, action_triggers) = parse_config_file(configfile)

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
    
    channel = connection.channel()

    #
    # Create a random queue name
    #
    queue_name = generate_queue_name()

    #
    # make sure you use auto_delete so the queue isn't left filling
    # with events when this program exists
    channel.queue_declare(queue=queue_name, auto_delete=True)

    #channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='watchlist.hit.#')
    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='ingress.event.process')


    channel.basic_consume(on_message, queue=queue_name)

    print
    print "Subscribed to events!"
    print ("Keep this script running to move computers matching specific CbER messages"
           "to a more restricted Enterprise Protection Policy!")
    print

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()

    connection.close()
