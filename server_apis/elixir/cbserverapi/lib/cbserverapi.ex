defmodule Cbserverapi do
  use GenServer
  require Logger

  import Exrabbit.Defs
    defmacro __using__(_) do
      quote location: :keep do
      require Logger
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
      def handle_info(stuff, state) do
        Logger.info("Unhandled bus message discarded: " <> inspect(stuff))
        { :noreply, state}
      end

      defp connect(key) do
        channel = getcreds |> Exrabbit.Utils.connect |> Exrabbit.Utils.channel
        queue = Exrabbit.Utils.declare_queue(channel)
        {:"queue.bind_ok"} = Exrabbit.Utils.bind_queue(channel, queue, "api.events", key)
        {:ok, [channel, queue]}
      end

      defp getcreds do
        Cbserverapi.Creds.getcreds
      end

      defoverridable [getcreds: 0]

    end
  end
end
