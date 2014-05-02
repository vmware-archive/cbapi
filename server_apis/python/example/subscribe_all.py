import pika
import pprint

def on_message(channel, method_frame, header_frame, body):

    pprint.pprint(body)
    print
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


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

    channel.queue_declare(queue='dennis')

    channel.queue_bind(exchange='api.events', queue='dennis', routing_key='#')

    channel.basic_consume(on_message, queue='dennis')
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()
