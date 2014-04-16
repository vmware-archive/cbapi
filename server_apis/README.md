# Carbon Black Server API 

## Overview

Carbon Black 4.2+ supports a rich array of asyncronous server-side notifications.

[MORE HERE]

## Intended Audience

The intended audience of this document is composed of two inter-related groups:

* Developers that wish to programmatically consume Carbon Black events
* Technologists that wish to take a peek "under the hood" of the Carbon Black server to better understand the inner workings

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

#### navigate to the newly-created cbapi/python/example directory

    [root@localhost repos]# pwd
    /root/repos
    [root@localhost repos]# cd cbapi/server_apis/python/example/
    [root@localhost example]# ls
    subscribe_all.py
    [root@localhost example]# 

#### use the example "subscribe_all.py" to see all event notifications on the Carbon Black server.

    [TODO]

## Notification Architecture

The Carbon Black server uses the Advanced Message Queuing Protocol (AMQP) to publish events of interest.  Any AMQP compliant client can subscribe to these notifications. 

## Notification Format 

All CBSAPI notifications are published in one of two formats:

* JSON 
* Google Protobufs (https://code.google.com/p/protobuf/)

The documentation below calls out in which format each notification type is published. 

## Notification Mechanisms

This document describes the underlying events published on the Carbon Black server message bus.  It is expected that these events will be consumed programmatically.

The Carbon Black server provides built-in mechanisms to expose these same events via syslog, e-mail, and HTTP POST.  The configuration of these alternate notification mechanisms is outside of the scope of this document.

## Notification Types

* Watchlist hit
  * Process Watchlist
  * Binary Watchlist
* Feed hit
  * Ingress
  * Storage
* New binary instance
  * [TODO] First instance of any endpoint observing a particular binary
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

| name              | type   | description | 
| ----------------- | -------|-------------| 
| `cb_version`      | string | Carbon Black server version|
| `childproc_count` | int32  | Total count of child processes created by this process|
| `filemod_count`   | int32  | Total count of file modifications made by this process|
| `group`           | string | Sensor group this sensor was assigned to at time of process execution|
| `host_type`       | string | Type of the computer: server, workstation, domain controller|
| `hostname`        | string | Hostname of the computer on which the process executed (at time of execution)|
| `id`              | string | For internal use|
| `last_update`     | string | Last activity in this process is endpoint local time.  Example: 2014-02-04T16:23:22.547Z |
| `modload_count`   | int32  | Total count of module loads in this process.| 
| `netconn_count`   | int32  | Total count of network connections made and received by this process.|
| `path`            | string | Full path to the executable file backing this process.|
| `process_md5`     | string | MD5 of the executable file backing this process.|
| `process_name`    | string | Filename of the executable backing this process.|
| `regmod_count`    | int32  | total count of registry modifications made by this process.|
| `segment_id`      | int32  | For internal use|
| `sensor_id`       | int32  | Endpoint identifier.|
| `servername`      | string | Name of Carbon Black server|
| `start`           | string | Start time of this process in endpoint local time. Example: 2014-02-04T16:23:22.516Z|
| `unique_id*       | string | Process unique Id|
| `username`        | string | User context in which the process executed.|
| `watchlist_id`    | int32  | Identifier of the watchlist that matched|
| `watchlist_name`  | string | Name of watchlist that matched|
| `cmdline          | string | Process command line|
| `parent_unique_id`| string| Parent process unique|

Example:

#### Binary Watchlist Hit

Channel: watchlist.[TODO]

| name                    | type   | description | 
| ----------------------- | -------| -------------| 
| `_version_`             | string | For internal use|
| `cb_version`            | string | Carbon Black Server version|
| `copied_mod_len`        | int32  | Number of bytes copied to server|
| `group`                 | string | First sensor group on which this binary was observed|
| `hostname`              | string | First endpoint hostname on which this binary was observed|
| `digsig_issuer`         | string | If digitally signed, the issuer.|
| `digsig_publisher`      | string | If digitally signed, the publisher.|
| `digsig_result`         | string | If digitally signed, the human-readable status. See notes.|
| `digsig_result_code`    | in32   | For internal use.|
| `digsig_sign_time`      | string | If digitally signed, the sign time.|
| `digsig_subject`        | string | If digitally signed, the subject.|
| `is_executable_image`   | bool   | True if the binary is a standalone executable (as compared to a library).|
| `is_64bit`              | bool   | True if architecture is x64 (versus x86)
| `md5`                   | string | MD5 of the binary|
| `observed_filename`     | string | Full path to the executable backing the process|
| `orig_mod_len`          | int32  | Size in bytes of the binary at the time of observation on the endpoint.|
| `server_added_timestamp`| string |The time this binary was first seen by the server.
| `servername`            | string | Name of Carbon Black server|
| `timestamp`             | string | Time binary was first observed (in endpoint time)|
| `watchlist_id`          | int32  | Identifier of the watchlist that matched|
| `watchlist_name`        | string | Name of watchlist that matched|
| `watchlists`            | JSON   | List of matching watchlists.|
| `file_version`          | string ||
| `product_name`          | string ||
| `company_name`          | string ||
| `internal_name`         | string ||
| `original_filename`     | string ||
| `file_desc`             | string ||
                                                                             
Notes:

The digsig_status field can be one of eight values:
* Signed
* Unsigned
* Bad Signature
* Invalid Signature
* Expired
* Invalid Chain
* Untrusted Root
* Explicit Distrust 

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
    "size": 320000,
    "compressed_size": 126857,
    "created_time": 1397248033.914
}
```
Notes:

* The Carbon Black Alliance client can be configured to delete binary store files from the Carbon Black server after uploading to the Alliance Server.  These files are still retrievable via the Carbon Black API, although there may be bandwidth or transfer time concerns.  
