defmodule Cbserverapi do
  use GenServer
  require Logger
  @key "#"
  @cfexchange "api.events"

  import Exrabbit.Defs

  def start_link(key) do
    GenServer.start_link(__MODULE__, {key, []}, name: String.to_atom("CB_" <> key))
  end

  def init({key, _state}) do
    {:ok, [channel, queue]} = connect(key)
    sub = basic_consume(queue: queue, no_ack: true)
    basic_consume_ok(consumer_tag: consumer_tag) = :amqp_channel.subscribe channel, sub, self
    {:ok, [consumer_tag, channel, queue]}
  end

  def handle_info({:"basic.consume_ok", consumer_tag}, state = [consumer_tag,_,_]) do
    {:noreply, state}
  end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.netconn"},
                   {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
                   binary}}, state) do
    netcon = Cbprotobuf.CbEventMsg.decode(binary)
    %Cbprotobuf.CbEventMsg{env: host, header: headermsg, network: network} = netcon
    #Logger.debug(inspect({routing_key, binary}))
    {:noreply, state}
  end
#  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", routing_key},
#                   {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
#                   binary}}, state) do
#    Logger.debug(inspect({routing_key, binary}))
#    {:noreply, state}
#  end
  def handle_info(stuff, state) do
    Logger.info(inspect(stuff))
    { :noreply, state}
  end

  defp connect do
    connect(@key)
  end

  defp connect(key) do
    channel = Cbserverapi.Creds.getcreds |> Exrabbit.Utils.connect |> Exrabbit.Utils.channel
    queue = Exrabbit.Utils.declare_queue(channel)
    {:"queue.bind_ok"} = Exrabbit.Utils.bind_queue(channel, queue, @cfexchange, key)
    IO.inspect key
    {:ok, [channel, queue]}
  end
end

