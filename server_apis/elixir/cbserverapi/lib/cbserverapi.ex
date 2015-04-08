defmodule Cbserverapi do
  @moduledoc """
  Implements a GenServer to receive and process sensor events from the RabbitMQ bus.
  As it is a GenServer you should treat it like a GenServer by using supervision
  trees and the like.

  The basic approach for using this module is to write your own OTP module which
  "use"'s this module.  This produle in turn "use"'s GenServer.  All messages from
  the bus are delivered via info (as opposed to cast / call) so you will need
  to write handle_info() functions for each sensor type you wish to process.

  Any undeclared message-types will emit a Logger.info message informing you of
  your lack of treatment.  To silence this feature, make your last handle_info()
  function match all.

  When you call start_link/1 to start your GenServer it takes only one arguement,
  a string for the routing key which, in the CarbonBlack world is the type of
  event you wish to consume.  To consume all, use "#".  To consume ingress.event.filemod,
  use "ingress.event.filemod".

  If you need to consume more than one type but not all you can either:
    * Specify all in /etc/cb/cb.conf and run multiple GenServers.
    * Specify only the events you want in /etc/cb/cb.conf and consume all "#"

  ## Minimal Module

      defmodule Cbdemo do
        use Cbserverapi
      end

  ## Usage of said module

      iex> Cbdemo.start_link("#")
  
  ## Example Processing

      defmodule Cbdemo do
        use Cbserverapi

        def handle_info({
          {:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.procstart"},
          {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
          binary}}, state) do
     
          ds = %Cbprotobuf.CbEventMsg{
            env: %Cbprotobuf.CbEnvironmentMsg{
              endpoint: %Cbprotobuf.CbEndpointEnvironmentMsg{
                HostId: _, SensorHostName: sensorhostname, SensorId: sensorid
              }
            }
          } = Cbprotobuf.CbEventMsg.decode(binary)
          Logger.debug(inspect(ds))
        end
      end

  From this point you can pattern-match any data you need from the headers or the ds
  datastructure.  Enjoy!

  See Also:

    * Cbserverapi - The GenServer you 'use'
    * Cbserverapi.Creds - Extracts credentials from /etc/cb/cb.conf file
    * Cbprotobuf - Provides supporting functions to decode protobuf-formatted binary data into records.

  """

  use GenServer
  require Logger

  import Exrabbit.Defs
    defmacro __using__(_) do
      quote location: :keep do
      require Logger

      def start_link(key) do
        GenServer.start_link(__MODULE__, {key, []}, name: String.to_atom("CB_" <> key))
      end

      def init(incoming) do
        Cbserverapi.init(incoming)
      end
    
      def handle_info({:"basic.consume_ok", _consumer_tag}, state) do
        {:noreply, state}
      end
      @before_compile unquote(__MODULE__)
    end
  end

  def init({key, _state}) do
    {:ok, [channel, queue]} = connect(key)
     sub = basic_consume(queue: queue, no_ack: true)
     basic_consume_ok(consumer_tag: consumer_tag) = :amqp_channel.subscribe channel, sub, self
     {:ok, HashDict.new}
  end
    
  defp connect(key) do
    channel = getcreds |> Exrabbit.Utils.connect |> Exrabbit.Utils.channel
    queue = Exrabbit.Utils.declare_queue(channel)
    {:"queue.bind_ok"} = Exrabbit.Utils.bind_queue(channel, queue, "api.events", key)
    {:ok, [channel, queue]}
  end

  def getcreds do
    Cbserverapi.Creds.getcreds
  end

  defmacro __before_compile__(_env) do
    quote do
      def handle_info(stuff, state) do
        Logger.info("Unhandled bus message discarded: " <> inspect(stuff))
        { :noreply, state}
      end
    end
  end
end
