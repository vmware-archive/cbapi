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

    [root@localhost carbonblack]# yum install git
    ...

    This step, and all subsequent steps, should be performed on a server with Carbon Black installed.

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
* Binary file upload complete

### Watchlist Hit  

#### Process Watchlist Hit

#### Binary Watchlist Hit

### Feed Hit

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
