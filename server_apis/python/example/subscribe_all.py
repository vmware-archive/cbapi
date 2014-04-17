import pika

def on_message(channel, method_frame, header_frame, body):
    print method_frame.delivery_tag
    print body
    print
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


if __name__ == "__main__":
    
    # Set the connection parameters to connect to rabbit-server1 on port 5672
    # on the / virtual host using the username "guest" and password "guest"
    credentials = pika.PlainCredentials('guest', 'guest')
    parameters = pika.ConnectionParameters('rabbit-server1',
                                           5672,
                                           '/',
                                           credentials)

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.basic_consume(on_message, 'test')
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()
