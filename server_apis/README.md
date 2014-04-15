# Carbon Black Server API 

## Overview

Carbon Black 4.2+ supports a rich array of asyncronous server-side notifications.

[MORE HERE]

## Using the Carbon Black Server API

The Carbon Black Server API (CBSAPI) is found on github at:

  https://github.com/carbonblack/cbapi/server_apis

The CBSAPI is a collection of documentation, example scripts, and a helper library to help subscribe to Carbon Black server notifications, parse and understand the contents of those notifications, and demonstrate common business logic uses of those notifications.

There is no requirement that the helper library be used. The helper library and example scripts are written in Python, but many common languages include all the underlying support required in order to subscribe to notifications from the Carbon Black server.  This includes Java and C/C++. 

### Getting started with CBSAPI

#### install git as needed

    This step, and all subsequent steps, should be performed on a server with Carbon Black installed.
    
    [root@localhost carbonblack]# yum install git
    ...

#### clone the github cbapi repository:

    [root@localhost carbonblack]# git clone https://github.com/carbonblack/cbapi.git
    Initialized empty Git repository in /root/repos/carbonblack/cbapi/.git/
    remote: Reusing existing pack: 80, done.
    remote: Counting objects: 25, done.
    remote: Compressing objects: 100% (25/25), done.
    Receiving objects: 100% (105/105), 38.03 KiB | 17 KiB/s, done.
    Resolving deltas: 100% (50/50), done.
    remote: Total 105 (delta 10), reused 0 (delta 0)

#### navigate to the newly-created cbapi directory

    [TODO]

#### use the example "subscribe_all.py" to see all event notifications on the Carbon Black server.

    [TODO]

## Notification Architecture

    [TODO]

## Notification Format 

All CBSAPI notifications are published in one of two formats:

* JSON 
* Google Protobufs (https://code.google.com/p/protobuf/)

The documentation below calls out in which format each notification type is published. 

## Notification Types

* Watchlist hit
  * Process Watchlist
  * Binary Watchlist
* Feed hit
  * Ingress
  * Storage
* New binary instance
  * First instance of an endpoint observing a particular binary
  * First instance of a sensor group observing a particular binary
* Binary file upload complete
* Raw endpoint events
  * File modification
    * File Creation
    * File Deletion
    * File First-Written-To
    * File Last-Written-To
* Registry modification
  * Registry Key Creation
    * Registry Key Deletion
    * Registry Value Write
    * Registry Value Deletion
 * Network Connection
* Process
  * Process creation
  * Process termination
* Binary information

### Watchlist Hit  

There are two types of watchlists:

* Process Watchlists
* Binary Watchlists

On watchlist "hit" (match), an event is published.  The bulk of the contents of the event is pulled from the underlying process or binary document.  As such, the event fields are different between the two event types.

#### Process Watchlist Hit

Channel: watchlist.[TODO]

| name               | type   | description | 
| ------------------ | -------|-------------| 
| `cb\_version`      | string | Carbon Black server version|
| `childproc\_count` | int32  | Total count of child processes created by this process|
| `filemod\_count`   | int32  | Total count of file modifications made by this process|
| `group`            | string | Sensor group this sensor was assigned to at time of process execution|
| `host\_type`       | string | Type of the computer: server, workstation, domain controller|
| `hostname`         | string | Hostname of the computer on which the process executed (at time of execution)|
| `id`               | string | For internal use|
| `last\_update`     | string | Last activity in this process is endpoint local time.  Example: 2014-02-04T16:23:22.547Z |
| `modload\_count`   | int32  | Total count of module loads in this process.| 
| `netconn\_count`   | int32  | Total count of network connections made and received by this process.|
| `path`             | string | Full path to the executable file backing this process.|
| `process\_md5`     | string | MD5 of the executable file backing this process.|
| `process\_name`    | string | Filename of the executable backing this process.|
| `regmod\_count`    | int32  | total count of registry modifications made by this process.|
| `segment\_id`      | int32  | For internal use|
| `sensor\_id`       | int32  | Endpoint identifier.|
| `servername`       | string | Name of Carbon Black server|
| `start`            | string | Start time of this process in endpoint local time. Example: 2014-02-04T16:23:22.516Z|
| `unique\_id*       | string | Process unique Id|
| `username`         | string | User context in which the process executed.|
| `watchlist\_id`    | int32  | Identifier of the watchlist that matched|
| `watchlist\_name`  | string | Name of watchlist that matched|
| `cmdline           | string | Process command line|
| `parent\_unique\_id`| string| Parent process unique|

Example:

#### Binary Watchlist Hit

Channel: watchlist.[TODO]

Example:

### Feed Hit

There are two types of feed events:

* Ingress
* Storage

[TODO] should we add a third for feed_searcher or should that be counted as storage?

Ingress feed events are published as the matching endpoint data arrives from the sensor.  These ingress feed events therefore provide the earliest available notification of the endpoint activity.  Ingress events are published prior to updating the data to the backend data store (SOLR), and therefore it may be up to twenty minutes before the data is discoverable via search.

Storage feed events are published as the data is written to the backend data store. These storage feed events are published upon updating the data store, but prior to committing the changes.  Threfore, it may be up to ten minutes before the data is discoverble via search. 

#### Ingress Feed Hit

Subscription Channel: feed.hit.process

`feed.hit.process` is a JSON structure with the following entries:

| name  | type   | description | 
| ----- | -------|-------------| 
| `process_id`   | string   | CB process key.  See Notes. | 
| `report_id`    | string   | Identifier of the report which included the matching IOC.  See notes. |
| `ioc_type`     | string   | One of "md5", "dns", "ipv4" | 
| `ioc_value`    | string   | The matching IOC. | 
| `feed_id`      | int | Identifier of the feed that included the matching report.  See notes. | 
| `feed_name`    | string | The  name of the feed that included the matching report. | 
| `created_time` | float | Timestamp of the feed match, measured in number of seconds since the epoch 

Example Event:

```
    {
      "process_id": " 9131443406494176380",
      "report_id": "dxmtest1_01",
      "ioc_type": "ipv4",
      "ioc_value": "172.16.100.22",
      "feed_id": 7,
      "feed_name": "dxmtest1",
      "created_time":1397240503.332
    }
```
Notes:

* The process_id field is the process key used to uniquely identify a process on the Carbon Black server.  For ingress feed hits, the process segment is not known.  The key can be used with the Carbon Black client API to query for the entire process document.

#### Storage Feed Hit

[TODO]

### New Binary Instance

The Carbon Black server publishes events the first time an executable file (binary) is observed in each of three scenarios:

1. First time it is observed on *any* endpoint
2. First time it is observed on an *individual* endpoint for the first time
3. First time it is observed on a sensor group for the first time

[TODO] Scenario 1 is not curently implemented
[TODO] Scenario 1 obviates the need for the "newly loaded modules" watchlist 

#### Scenario 1: Observed on any Endpoint

Subscription Channel: [TODO]

#### Scenario 2: Observed on an individual endpoint for the first time

Subscription Channel: cbsolr.newhost.observed

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "observed_name": "FS-HQ|1021",
    "created_time": 1397248033.914
}
```

##### Scenario 3: Observed within a sensor group for the first time

Subscription Channel: cbsolr.newgroup.observed

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "observed_name": "Default Group",
    "created_time": 1397248033.914
}
```

#### New Binary File Arrival

The Carbon Black server can be configured to store a copy of all unique binary (executable) files observed on endpoints.  This includes Windows PE files such as EXEs and DLLs, Linux ELF files, and similar.  Upon the arrival of a new binary file, a binarystore event is published.

This event provides an easy way to trigger custom analysis of a binary, including static or dynamic anaysis, integration with a third-party analysis system, or custom archiving.

Subscription Channel: binarystore.file.added
 
`binarystore.file.added` is a JSON structure with the following entries:

| name  | type   | description | 
| ----- | -------|-------------| 
| `md5`          | string   | MD5 sum of the binary file. | 
| `size`         | int32    | Size of the original binary, in bytes. |
| `ioc_type`     | int32    | Size of the zip archive containing the binary file on the Carbon Black server | 
| `created_time` | float    | Timestamp of the binary file addtion, measured in number of seconds since the epoch 

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "size" :320000,
    "compressed_size": 126857,
    "created_time": 1397248033.914
}
```
Notes:

* The Carbon Black Alliance client can be configured to delete binary store files from the Carbon Black server after uploading to the Alliance Server.  These files are still retrievable via the Carbon Black API, although there may be bandwidth or transfer time concerns.  
