import sys
import pika
import pprint
import random
import optparse
import json
import requests

def blacklist_binary(md5):
    """
    Performs a POST to the Carbon Black Server API for blacklisting an MD5 hash
    """
    print "blacklisting md5:%s" % (md5)

    global cbtoken
    global cbserver

    headers = {'X-AUTH-TOKEN': cbtoken}

    data = {"md5hash": md5, 
        "text":"Auto-Blacklist From Watchlist", 
        "last_ban_time":0, 
        "ban_count":0,
        "last_ban_host":0,
        "enabled":True }

    r = requests.post("https://%s/api/v1/banning/blacklist" % (cbserver), 
        headers = headers, 
        data = json.dumps(data),
        verify = False)

    if r.status_code == 409:
        print "This md5 hash is already blacklisted"
    elif r.status_code == 200:
        print "Carbon Black Server API Success"
    else:
        print "CarbonBlack Server API returned an error: %d" % (r.status_code)
        print "Be sure to check the Carbon Black API token"

def on_message(channel, method_frame, header_frame, body):
    """
    Callback function which filters out the feeds we care about.
    """

    try:
        if "application/json" == header_frame.content_type:

            if method_frame.routing_key == 'watchlist.hit.binary':
                print "watchlist.hit.binary consume"
                
                parsed_json = json.loads(body)
                print parsed_json
                lst = parsed_json['docs']
                for item in lst:
                    blacklist_binary(item['md5'])
            
            elif method_frame.routing_key == 'watchlist.hit.process':
                print "watchlist.hit.process consume"
                
                parsed_json = json.loads(body)
                lst = parsed_json['docs']
                for item in lst:
                    blacklist_binary(item['process_md5'])

    except Exception, e:
        print e
    finally:
        # need to make sure we ack the messages so they don't get left un-acked in the queue
        # we set multiple to true to ensure that we ack all previous messages
        channel.basic_ack(delivery_tag=method_frame.delivery_tag, multiple=True)

    return

def generate_queue_name():
    """
    generates a random queue name
    """
    return str(random.randint(0,10000)) + "-" + str(random.randint(0,100000))

def build_cli_parser():

    parser = optparse.OptionParser(usage="%prog [options]", 
        description="Example CBSAPI script to consume published events")
    
    parser.add_option("-p", "--password", action="store", default="", dest="password",
        help="RabbitMQ password; see /etc/cb/cb.conf\nDefault is an empty string")
    
    parser.add_option("-u", "--usename", action="store", default="cb", dest="username",
        help="RabbitMQ username; see /etc/cb/cb.conf\nDefault is cb")
    
    parser.add_option("-s", "--cbserverip", action="store", default="localhost", dest="cbserver", 
        help="Carbon Black server IP for rabbitmq server\nDefault is localhost")
    
    parser.add_option("-t", "--cbtoken", action="store", default="", dest="cbtoken",
        help='Carbon Black API token\nDefault is an empty string')

    return parser

if __name__ == "__main__":

    #    
    # build the command line parser and ensure the required password option was provided
    #
    parser = build_cli_parser()
    (options, args) = parser.parse_args()

    global cbtoken 
    cbtoken = options.cbtoken
    global cbserver
    cbserver = options.cbserver
    
    #
    # Set the connection parameters to connect to to the rabbitmq:5004
    # using the supplied username and password
    #
    credentials = pika.PlainCredentials(options.username, 
        options.password)
    
    #
    # Create our parameters for pika
    #
    parameters = pika.ConnectionParameters(options.cbserver,
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

    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='#')

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