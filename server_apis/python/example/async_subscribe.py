import logging
import pika

logger = logging.getlogger(__name__)

"""
Based Heavily on the async example provided by PIKA.

Needs to be expanded to handle publishing
"""


class CBAsyncConsumer(object):
    """
    Fully Asyncronous consumer with mild recovery from connections built in
    """

    def __init__(self, amqp_url, exchange, queue, routing_key, arguments,
                 exchange_type='direct', exchange_durable=False, auto_del=True, worker=lambda x: None):
        """ Create a new instance of a consumer class to fully handle the work with the RabbitMQ server.
        Once the objecty has been fully created, calling <object>.run() will start the connection and work

        :param amqp_url: URL of RabbitMQ connection
        :type amqp_url: String
        :param exchange: The Exchange name to utilize with the consumer
        :type exchange: string
        :param queue: The queue name to generate on connection
        :type queue: String
        :param routing_key: The routing key to use
        :type routing_key: String
        :param exchange_type: The type of exchange: direct,topic, fanout, header
            (https://www.rabbitmq.com/tutorials/amqp-concepts.html)
        :type exchange_type: String (direct,topic, fanout, header)
        :param exchange_durable: Whether the exchange should persist
        :type exchange_durable: Bool
        :param auto_del: Auto-delete the queue when no consumers are connected
        :type auto_del: Bool
        :param arguments: Extended arguments to pass to the queue declaration
        :type arguments: Dictionary
        :param worker: A function that can be called to "do work"
        :type worker: function
        :return: RabbitMQ Consumer
        :rtype: CBAsyncConsumer object

        :TODO amqp_url: Convert this to a connection call from the pika library
        """

        self._connection = None
        self._channel = None
        self._closing = False
        self._consumer_tag = None
        self._url = amqp_url
        self.exchange = exchange
        self.exchange_type = exchange_type
        self.queue = queue
        self.auto_del = auto_del
        self.arguments = arguments
        self.routing_key = routing_key
        self.exchange_durable = exchange_durable
        self.worker = worker

    def connect(self):
        """Connects to RabbitMQ, returning the connection handle.
        If the connection is established, the on_connection_open method
        will be invoked by pika as a callback.

        :return: RabbitMQ Connection handle
        :rtype: pika.SelectConnection

        :TODO: Expose stop_ioloop_on_close boolean
        """
        logger.info('Connecting to %s', self._url)
        return pika.SelectConnection(pika.URLParameters(self._url),
                                     self.on_connection_open,
                                     stop_ioloop_on_close=False)

    def close_connection(self):
        """ Closes the connection to RabbitMQ.

        :return: Returns nothing
        :rtype: None"""
        logger.info('Closing connection')
        self._connection.close()

    def add_on_connection_close_callback(self):
        """ Adds a callback after a connection has successfully been made to RabbitMQ.This method adds an on close
        callback that will be invoked by pika in the event that RabbitMQ closes the connection to the publisher
        unexpectedly.

        :return: Returns nothing
        :rtype: None"""
        logger.debug('Adding connection close callback')
        self._connection.add_on_close_callback(self.on_connection_closed)

    def on_connection_closed(self, connection, reply_code, reply_text):
        """ When the connection to RabbitMQ is closed unexpectedly this method is called.
        The default behavior is to attempt to reconnect to RabbitMQ after 5 seconds.

        :param connection: The closed connection obj (This is unused as we have it in class scope)
        :type connection: pika.connection.Connection connection
        :param reply_code: The server provided reply_code if given
        :type reply_code: int
        :param str reply_text: The server provided reply_text if given
        :type reply_text: str

        :return: Returns nothing
        :rtype: None"""
        self._channel = None
        if self._closing:
            self._connection.ioloop.stop()
        else:
            logger.warning('Connection closed, reopening in 5 seconds: (%s) %s',
                           reply_code, reply_text)
            self._connection.add_timeout(5, self.reconnect)

    def on_connection_open(self, unused_connection):
        """ Performs the act of actually opening the handle for us after the connection to RabbitMQ has completed

        :param unused_connection: Unused select connection object, might be good to modify the object in the future
        if needed
        :type unused_connection: pika.SelectConnection

        :return: Returns nothing
        :rtype: None"""
        logger.info('Connection opened to rabbitMQ server')
        self.add_on_connection_close_callback()
        self.open_channel()

    def reconnect(self):
        """ Auto-reconnect method called by "on_connection_closed"

        :return: Returns nothing
        :rtype: None"""
        # This is the old connection IOLoop instance, stop its ioloop
        self._connection.ioloop.stop()

        logger.warning('Reopening Connection')
        if not self._closing:

            # Create a new connection
            self._connection = self.connect()

            # There is now a new connection, needs a new ioloop to run
            self._connection.ioloop.start()

    def add_on_channel_close_callback(self):
        """This method tells pika to call the on_channel_closed method if
        RabbitMQ unexpectedly closes the channel.

        """
        logger.debug('Adding channel close callback')
        self._channel.add_on_close_callback(self.on_channel_closed)

    def on_channel_closed(self, channel, reply_code, reply_text):
        """Invoked by pika when RabbitMQ unexpectedly closes the channel.
        Channels are usually closed if you attempt to do something that
        violates the protocol, such as re-declare an exchange or queue with
        different parameters. In this case, we'll close the connection
        to shutdown the object.

        :param channel: The closed channel
        :type channel: pika.channel.Channel
        :param reply_code: The numeric reason the channel was closed
        :type reply_code: int
        :param reply_text: The text reason the channel was closed
        :type reply_text: str

        """
        logger.warning('Channel %i was closed: (%s) %s',
                       channel, reply_code, reply_text)
        self._connection.close()

    def on_channel_open(self, channel):
        """ Passes the channel object to the connection handle now that the channel is open and
        declares the exchange to use.

        :param channel: The channed utilized for connection strings
        :type channel: pika.channel.Channel

        """
        logger.debug('Channel opened')
        self._channel = channel
        self.add_on_channel_close_callback()
        self.setup_exchange(self.exchange)

    def setup_exchange(self, exchange_name):
        """ Initializes the RabbitMQ exchange for use. When it is complete, the on_exchange_declareok method will
        be invoked by pika.

        :param exchange_name: The name of the exchange to declare
        :type exchange_name: str or unicode

        """
        logger.info('Declaring exchange %s - Exchange Type: %s Exchange Durability:%s', exchange_name,
                    self.exchange_type, self.exchange_durable)
        self._channel.exchange_declare(self.on_exchange_declareok,
                                       exchange_name,
                                       self.exchange_type,
                                       durable=self.exchange_durable)

    def on_exchange_declareok(self, unused_frame):
        """ Invoked by pika when RabbitMQ has finished the Exchange.Declare RPC
        command.

        :param pika.Frame.Method unused_frame: Exchange.DeclareOk response frame
        :type unused_frame: pika.Frame.Method

        """
        logger.debug('Exchange declared')
        self.setup_queue(self.queue)

    def setup_queue(self, queue_name):
        """Setup the queue on RabbitMQ by invoking the Queue.Declare RPC
        command. When it is complete, the on_queue_declareok method will
        be invoked by pika.

        :param queue_name: The name of the queue to declare.
        :type queue_name: str or unicode

        """
        logger.info('Declaring queue %s - auto_delete: %s - arguments %s', queue_name, self.auto_del, self.arguments)
        self._channel.queue_declare(self.on_queue_declareok, queue_name,
                                    auto_delete=self.auto_del,
                                    arguments=self.arguments)

    def on_queue_declareok(self, method_frame):
        """ Bind the queue and exchange together with the routing key by issuing the Queue.Bind
        RPC command. When this command is complete, the on_bindok method will
        be invoked by pika.

        :param method_frame: The Queue.DeclareOk frame
        :type method_frame: pika.frame.Method

        """
        logger.info('Binding Exchange:%s - Queue:%s - Routing Key:%s',
                    self.exchange, self.queue, self.routing_key)
        self._channel.queue_bind(self.on_bindok, self.queue,
                                 self.exchange, self.routing_key)

    def add_on_cancel_callback(self):
        """ Add a callback that will be invoked if RabbitMQ cancels the consumer
        for some reason. If RabbitMQ does cancel the consumer,
        on_consumer_cancelled will be invoked by pika.

        """
        logger.debug('Adding consumer cancellation callback')
        self._channel.add_on_cancel_callback(self.on_consumer_cancelled)

    def on_consumer_cancelled(self, method_frame):
        """ Invoked by pika when RabbitMQ sends a Basic.Cancel for a consumer
        receiving messages.  When this is called we close the channel being used by RabbitMQ.

        :param method_frame: The Basic.Cancel frame
        :type method_frame: pika.frame.Method

        """
        logger.debug('Consumer was cancelled remotely, shutting down: %r', method_frame)
        if self._channel:
            self._channel.close()

    def acknowledge_message(self, delivery_tag):
        """ Acknowledges the message delivery from RabbitMQ by sending a
        Basic.Ack RPC method for the delivery tag.

        :param delivery_tag: The delivery tag from the Basic.Deliver frame
        :type delivery_tag: int

        """
        logger.debug('Acknowledging message %s', delivery_tag)
        self._channel.basic_ack(delivery_tag)

    def on_message(self, unused_channel, basic_deliver, properties, body):
        """ WHERE ALL THE WORKER MAGIC HAPPENS

        Invoked by pika when a message is delivered from RabbitMQ. The
        channel is passed in, but it is only there for future use. The basic_deliver object that
        is passed in carries the exchange, routing key, delivery tag and
        a redelivered flag for the message. The properties passed in is an
        instance of BasicProperties with the message properties and the body
        is the message that was sent.

        :param pika.channel.Channel unused_channel: The channel object
        :type unused_channel: pika.channel.Channel
        :param pika.Spec.Basic.Deliver: basic_deliver method
        :param pika.Spec.BasicProperties: properties
        :param str|unicode body: The message body

        """
        logger.debug('Received message # %s from %s', basic_deliver.delivery_tag, properties.app_id)
        self.worker(body)

        self.acknowledge_message(basic_deliver.delivery_tag)

    def on_cancelok(self, unused_frame):
        """ Invoked by pika when RabbitMQ acknowledges the cancellation of a consumer.
        At this point we will close the channel.This will invoke the on_channel_closed method once the channel has been
        closed, which will in-turn close the connection.

        :param unused_frame: The Basic.CancelOk frame
        :type unused_frame: pika.frame.Method

        """
        logger.debug('RabbitMQ acknowledged the cancellation of the consumer')
        self.close_channel()

    def stop_consuming(self):
        """Tell RabbitMQ that you would like to stop consuming by sending the
        Basic.Cancel RPC command.

        """
        if self._channel:
            logger.debug('Sending a Basic.Cancel RPC command to RabbitMQ')
            self._channel.basic_cancel(self.on_cancelok, self._consumer_tag)

    def start_consuming(self):
        """Sets up the consumer by first calling add_on_cancel_callback so that the object is notified if RabbitMQ
        cancels the consumer. It then issues the Basic.Consume RPC command which returns the consumer tag that is
        used to uniquely identify the consumer with RabbitMQ. We keep the value to use it when we want to
        cancel consuming. The on_message method is passed in as a callback pika
        will invoke when a message is fully received.

        """
        logger.debug('Issuing consumer related RPC commands')
        self.add_on_cancel_callback()
        self._consumer_tag = self._channel.basic_consume(self.on_message,
                                                         self.queue)

    def on_bindok(self, unused_frame):
        """ Invoked by pika when the Queue.Bind method has completed. At this point we will start consuming messages
        by calling start_consuming which will invoke the needed RPC commands to start the process.

        :param pika.frame.Method unused_frame: The Queue.BindOk response frame
        :type unused_frame: pika.frame.Method

        """
        logger.debug('Queue %s bound', self.queue)
        self.start_consuming()

    def close_channel(self):
        """Call to close the channel with RabbitMQ cleanly by issuing the
        Channel.Close RPC command.

        """
        logger.debug('Closing the channel')
        self._channel.close()

    def open_channel(self):
        """Open a new channel with RabbitMQ by issuing the Channel.Open RPC
        command. When RabbitMQ responds that the channel is open, the
        on_channel_open callback will be invoked by pika.

        """
        logger.debug('Creating a new channel')
        self._connection.channel(on_open_callback=self.on_channel_open)

    def run(self):
        """Run the example consumer by connecting to RabbitMQ and then
        starting the IOLoop to block and allow the SelectConnection to operate.

        """
        logger.debug('Starting the consumer')
        self._connection = self.connect()
        self._connection.ioloop.start()

    def stop(self):
        """Cleanly shutdown the connection to RabbitMQ by stopping the consumer
        with RabbitMQ. When RabbitMQ confirms the cancellation, on_cancelok
        will be invoked by pika, which will then closing the channel and
        connection. The IOLoop is started again because this method is invoked
        when CTRL-C is pressed raising a KeyboardInterrupt exception. This
        exception stops the IOLoop which needs to be running for pika to
        communicate with RabbitMQ. All of the commands issued prior to starting
        the IOLoop will be buffered but not processed.

        """
        logger.debug('Stopping the consumer')
        self._closing = True
        self.stop_consuming()
        self._connection.ioloop.start()
        logger.debug('Stopped consumer')


def main():
    """
    Example of how to use the abuse class.
    
    We were able to run at about 16k msg/s before rabbitmq
    had issues without taxing the local system.
    """
    from proto.sensor_events_pb2 import *
    
    LOG_FORMAT = ('%(levelname) -10s %(asctime)s %(name) -30s %(funcName) '
                  '-35s %(lineno) -5d: %(message)s')

    def worker_func(message):
        """
        Simple example function to do work on all messages found
        
        This in particular parses through all filemod events for files that are
        being written such as exe's and swf's
        """
        cb_e_msg = CbEventMsg()
        cb_e_msg.ParseFromString(message)
        for l in cb_e_msg.strings:
            if l.utf8string.split('.')[-1] in ('exe', 'swf'):
                logger.info('PID:%s Sensor Hostname:%s File:%s', cb_e_msg.header.process_pid,
                            cb_e_msg.env.endpoint.SensorHostName, l.utf8string)

    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    cb_cons = CBAsyncConsumer(amqp_url='amqp://<>:<>@SERVER:5004/',
                              exchange='api.events',
                              queue='EXE-SWF-WriteWatch',
                              routing_key='ingress.event.filemod',
                              exchange_type='topic',
                              exchange_durable=True,
                              arguments={'x-max-length': 10000},
                              worker=worker_func
                              )
    try:
        cb_cons.run()
    except KeyboardInterrupt:
        cb_cons.stop()


if __name__ == '__main__':
    main()
