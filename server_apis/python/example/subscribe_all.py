import sys
import pika
import pprint
import random
import optparse
import eventsv2_pb2 as cpb

def on_message(channel, method_frame, header_frame, body):

    try:

        print method_frame.routing_key

        if "application/protobuf" == header_frame.content_type:
            x = cpb.CbEventMsg()
            x.ParseFromString(body)
            print "EVENT: %s" % x

        elif "application/json" == header_frame.content_type:
            print "json"
        else:
            print header_frame.content_type
        #pprint.pprint(body)
        print

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
    parser = optparse.OptionParser(usage="%prog [options]", description="Example CBSAPI script to consume published events")
    parser.add_option("-p", "--password", action="store", default=None, dest="password",
                      help="RabbitMQ password; see /etc/cb/cb.conf")
    parser.add_option("-u", "--usename", action="store", default="cb", dest="username",
                      help="RabbitMQ username; see /etc/cb/cb.conf")
    return parser

if __name__ == "__main__":
    
    # build the command line parser and ensure that the required password option was provided
    #
    parser = build_cli_parser()
    opts, args = parser.parse_args(sys.argv)
    if not opts.password:
        print "Missing password param; run with -h for usage"
        sys.exit(-1)
    
    # Set the connection parameters to connect to rabbit-server1 on port 5672
    # on the / virtual host using the username "guest" and password "guest"
    credentials = pika.PlainCredentials(opts.username, opts.password)
    parameters = pika.ConnectionParameters('localhost',
                                           5004,
                                           '/',
                                           credentials)

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    queue_name = generate_queue_name()

    # make sure you use auto_delete so the queue isn't left filling
    # with events when this program exists.
    channel.queue_declare(queue=queue_name, auto_delete=True)

    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='#')

    channel.basic_consume(on_message, queue=queue_name)
   
    print "-> Subscribed!"
 
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
   
    connection.close()
