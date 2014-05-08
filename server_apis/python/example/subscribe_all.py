import pika
import pprint
import random

def on_message(channel, method_frame, header_frame, body):



    try:

        print method_frame.routing_key

        if "application/protobuf" == header_frame.content_type:
            print "protobuf"
        elif "application/json" == header_frame.content_type:
            print "json"
        else:
            print header_frame.content_type
        #pprint.pprint(body)
        print
        #channel.basic_ack(delivery_tag=method_frame.delivery_tag)

    except Exception, e:
        print e

    return

def generate_queue_name():
    """
    generates a random queue name
    """
    return str(random.randint(0,10000)) + "-" + str(random.randint(0,100000))

if __name__ == "__main__":
    
    # Set the connection parameters to connect to rabbit-server1 on port 5672
    # on the / virtual host using the username "guest" and password "guest"
    credentials = pika.PlainCredentials('cb', '97oQ7kQTdByddQjy')
    parameters = pika.ConnectionParameters('localhost',
                                           5004,
                                           '/',
                                           credentials)

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    queue_name = generate_queue_name()

    channel.queue_declare(queue=queue_name)

    channel.queue_bind(exchange='api.events', queue=queue_name, routing_key='#')

    channel.basic_consume(on_message, queue=queue_name)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()
