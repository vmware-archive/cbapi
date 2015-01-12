# eventExporter.py Example Script

## Purpose

The eventExporter.py example script demonstrates mechanisms to "tap" into the Carbon Black ingress data stream to perform arbitrary processing, logging, or external storage.

## Background

The Carbon Black Enterprise Server (CB Server or cbent) accepts data from Carbon Black sensors in the form of sensor event logs.  These event logs are encoded using length-value encoding and the event types are encoded with Google Protocol Buffers (https://code.google.com/p/protobuf).  The event logs include events from one or more processes on a single endpoint.  The events are of various types, including:

* NetConns (network connections)
* ModLoads (library loads, such as DLL or EXE)
* FileMods (file creation, deletion, or modification)
* RegMods (registry key creation, key deletion, value creation/modification, and value deletion)
* XProcess (opens of external processes) (new to CB 5.0)
* RemoteThread (creations of threads in external processes) (new to CB 5.0)
* ModInfo (description of a newly-observed binary such as EXE or DLL)
* Process (process startup and termination)

The events are demultiplexed on a per-process basis and passed to the Carbon Black data backend.

## Prerequisites

* The script must run on the Carbon Black Enterprise Server. 
* If the Carbon Black Server deployment is a cluster deployment, the script must run on every minion node of interest
* The script must run with root privileges
* The server must be configured to "save off" incoming sensor event logs OR the server must be configured to publish incoming events of interest over the RabbitMQ pub/sub bus.

### Configuring the Carbon Black Server to Save Off Sensor Event Logs

1. Stop the Carbon Black server using `service cb-enterprise stop`

2. Create a new file `/etc/cb/datastore/archive.properties` with the following content:

        cbfs-http.log-archive.type=filesystem
        cbfs-http.log-archive.filesystem.location=/path/to/archive/dir
        cbfs-http.log-archive.filesystem.queue-size=100

3. Ensure that the directory pointed to by cbfs-http.log-archive.filesystem.location is writable by the cb user:

        chown cb:cb /path/to/archive/dir

4. Restart the Carbon Black server using `service cb-enterprise start`

WARNING: The Carbon Black Enterprise server does NOT manage the disk usage of the event log archive directory.  Independent mechanisms must be used to avoid excessive disk usage.

### Configuring the Carbon Black Server to Publish Raw Events to the Pub/Sub Bus

Please see the "Raw Endpoint Events" section of the README.md in the root of the Carbon Black Server API (CBSAPI) documentation.

## Modes Of Operation

The eventExporter.py example script can be configured to run in three modes of operation:

1. On a single event log file with the -f option.
2. On a single directory of log files with the -d option.
3. Automatically identify hte event log archive directory by parsing archive.properties with the -a option.

## Output Options

1. Output can be done in JSON formation using --output json
2. Output can be done in human-readable 'table' format using --output table

## Other Options

The -r option can be used to automatically remove event logs after processing. 
