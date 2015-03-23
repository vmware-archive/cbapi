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
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.procstart"},
                   {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
                   binary}}, state) do
    %Cbprotobuf.CbEventMsg{

    env: %Cbprotobuf.CbEnvironmentMsg{endpoint: %Cbprotobuf.CbEndpointEnvironmentMsg{HostId: _, SensorHostName: sensorhostname, SensorId: sensorid},
                                      server: %Cbprotobuf.CbServerEnvironmentMsg{NodeId: servernodeid}},
    header:   %Cbprotobuf.CbHeaderMsg{filepath_string_guid: filepathguid, process_create_time: processcreatetime,
                                      process_filepath_string_guid: processfilepathstringguid, process_guid: processguid,
                                      process_md5: processmd5, process_path: processpath, process_pid: processpid, timestamp: timestamp, version: 4},
    process: %Cbprotobuf.CbProcessMsg{commandline: commandline, created: created, creationobserved: creationobserved, deprecated: deprecated, expect_followon_w_md5: expectmd5, have_seen_before: haveseenbefore, md5hash: md5hash, parent_create_time: parentcreatetime, parent_guid: parentguid, parent_md5: parentmd5, parent_path: parentpath, parent_pid: parentpid, pid: pid, uid: uid, username: username},
                           strings: strings} = Cbprotobuf.CbEventMsg.decode(binary)
    Logger.debug(inspect({sensorhostname, sensorid, servernodeid}))
    Logger.debug(inspect({filepathguid, processcreatetime, processfilepathstringguid, processguid, processmd5, processpath, processpid, timestamp}))
    Logger.debug(inspect({commandline, created, creationobserved, deprecated, expectmd5, haveseenbefore, md5hash, parentcreatetime, parentguid, parentmd5, parentpath, parentpid, pid, uid, username}))
    Logger.debug(inspect(strings))
    {:noreply, state}
  end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.procend"},
                   {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
                   binary}}, state) do
    procds = Cbprotobuf.CbEventMsg.decode(binary)
#    Logger.debug(inspect({:procend, procds}))
    {:noreply, state}
  end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.childproc"},
                   {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
                   binary}}, state) do
    procds = Cbprotobuf.CbEventMsg.decode(binary)
#    Logger.debug(inspect({:childproc, procds}))
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
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.filemod"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "cmd.feed.synchronize"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.moduleload"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "binarystore.file.added"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "watchlist.hit.binary"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "feed.storage.hit.binary"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "feed.storage.hit.process"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.regmod"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "ingress.event.crossprocopen"}, _}, state) do {:noreply, state} end
  def handle_info({{:"basic.deliver", _consumer_tag, _delivery_tag, _redelivered, "api.events", "feed.ingress.hit.process"}, _}, state) do {:noreply, state} end

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




# 03:03:12.455 [debug] {:procend, %Cbprotobuf.CbEventMsg{blocked: nil, childproc: nil, crossproc: nil, env: %Cbprotobuf.CbEnvironmentMsg{endpoint: %Cbprotobuf.CbEndpointEnvironmentMsg{HostId: 0, SensorHostName: "nukefromorbit.local", SensorId: 1}, server: %Cbprotobuf.CbServerEnvironmentMsg{NodeId: 0}}, filemod: nil, header: %Cbprotobuf.CbHeaderMsg{bootid: nil, eventid: nil, filepath_string_guid: 3926010920644000209, magic: nil, process_create_time: 130715532333459530, process_filepath_string_guid: nil, process_guid: -7593703415825946762, process_md5: nil, process_path: nil, process_pid: nil, timestamp: 130715533545282680, version: 4}, modload: nil, module: nil, network: nil, process: %Cbprotobuf.CbProcessMsg{commandline: nil, created: false, creationobserved: nil, deprecated: nil, expect_followon_w_md5: nil, have_seen_before: nil, md5hash: <<33, 36, 144, 160, 149, 38, 216, 3, 28, 40, 3, 186, 119, 173, 224, 61>>, parent_create_time: 130713745065256120, parent_guid: -1394285741804287137, parent_md5: <<3, 220, 73, 111, 89, 8, 141, 191, 205, 106, 71, 120, 37, 91, 212, 234>>, parent_path: nil, parent_pid: 1, pid: nil, uid: nil, username: nil}, regmod: nil, stats: nil, strings: [], tamperAlert: nil, vtload: nil, vtwrite: nil}}

#03:03:12.243 [debug] {:childproc, %Cbprotobuf.CbEventMsg{blocked: nil, childproc: %Cbprotobuf.CbChildProcessMsg{child_guid: 5432391300982968806, create_time: nil, created: true, md5hash: <<39, 229, 127, 218, 246, 25, 221, 172, 14, 115, 166, 27, 237, 209, 17, 54>>, parent_guid: -1394285741804287137, path: "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookSourceSync.app/Contents/MacOS/AddressBookSourceSync", pid: 20997}, crossproc: nil, env: %Cbprotobuf.CbEnvironmentMsg{endpoint: %Cbprotobuf.CbEndpointEnvironmentMsg{HostId: 0, SensorHostName: "nukefromorbit.local", SensorId: 1}, server: %Cbprotobuf.CbServerEnvironmentMsg{NodeId: 0}}, filemod: nil, header: %Cbprotobuf.CbHeaderMsg{bootid: nil, eventid: nil, filepath_string_guid: nil, magic: nil, process_create_time: 130715533782483580, process_filepath_string_guid: nil, process_guid: -1394285741804287137, process_md5: nil, process_path: nil, process_pid: nil, timestamp: 130715533782483580, version: 4}, modload: nil, module: nil, network: nil, process: nil, regmod: nil, stats: nil, strings: [], tamperAlert: nil, vtload: nil, vtwrite: nil}}

# 03:03:12.783 [debug] {:procstart, %Cbprotobuf.CbEventMsg{blocked: nil, childproc: nil, crossproc: nil, env: %Cbprotobuf.CbEnvironmentMsg{endpoint: %Cbprotobuf.CbEndpointEnvironmentMsg{HostId: 0, SensorHostName: "nukefromorbit.local", SensorId: 1}, server: %Cbprotobuf.CbServerEnvironmentMsg{NodeId: 0}}, filemod: nil, header: %Cbprotobuf.CbHeaderMsg{bootid: nil, eventid: nil, filepath_string_guid: -3294827462833805279, magic: nil, process_create_time: 130715533782483580, process_filepath_string_guid: nil, process_guid: 5432391300982968806, process_md5: nil, process_path: nil, process_pid: nil, timestamp: 130715533782483580, version: 4}, modload: nil, module: nil, network: nil, process: %Cbprotobuf.CbProcessMsg{commandline: "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookSourceSync.app/Contents/MacOS/AddressBookSourceSync", created: true, creationobserved: true, deprecated: nil, expect_followon_w_md5: nil, have_seen_before: nil, md5hash: <<39, 229, 127, 218, 246, 25, 221, 172, 14, 115, 166, 27, 237, 209, 17, 54>>, parent_create_time: 130713745065256120, parent_guid: -1394285741804287137, parent_md5: <<3, 220, 73, 111, 89, 8, 141, 191, 205, 106, 71, 120, 37, 91, 212, 234>>, parent_path: "/sbin/launchd", parent_pid: 1, pid: nil, uid: nil, username: "red"}, regmod: nil, stats: nil, strings: [%Cbprotobuf.CbStringMsg{guid: -3294827462833805279, string_type: nil, utf8string: "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookSourceSync.app/Contents/MacOS/AddressBookSourceSync"}], tamperAlert: nil, vtload: nil, vtwrite: nil}}
