# Carbon Black Server API 

## Overview

Carbon Black 4.2+ supports a rich array of asynchronous server-side notifications.

This document describes these notifications, how to subscribe to these notifications, and the format of the notifications themselves.

## Intended Audience

The intended audience of this document is composed of two inter-related groups:

* Developers that wish to programmatically consume Carbon Black events
* Technologists that wish to take a peek "under the hood" of the Carbon Black server to better understand the inner workings

## Using the Carbon Black Server API

The Carbon Black Server API (CBSAPI) is found on github at:

  https://github.com/carbonblack/cbapi/

in the "server_apis" directory.

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

#### install the pika package

The example scripts depend on the "Pika" package.  Documentation is available at http://pika.readthedocs.org/en/latest/.

    [root@localhost example]# easy_install pika
    Searching for pika
    Reading http://pypi.python.org/simple/pika/
    Best match: pika 0.9.13
    Downloading https://pypi.python.org/packages/source/p/pika/pika-0.9.13.tar.gz#md5=1a1be22edf4c1eae84dcc3d0df9ef216
    Processing pika-0.9.13.tar.gz
    Running pika-0.9.13/setup.py -q bdist_egg --dist-dir /tmp/easy_install-bc5nZk/pika-0.9.13/egg-dist-tmp-Ii6kPF
    Adding pika 0.9.13 to easy-install.pth file

    Installed /usr/lib/python2.6/site-packages/pika-0.9.13-py2.6.egg
    Processing dependencies for pika
    Finished processing dependencies for pika
    [root@localhost example]# 
 
#### use the example "subscribe_all.py" to see all event notifications on the Carbon Black server.

The 'subscribe_all.py' example script is found at:

    `server_apis/python/example`

## Notification Architecture

The Carbon Black server uses the Advanced Message Queuing Protocol (AMQP) to publish events of interest.  Any AMQP compliant client can subscribe to these notifications. 

## Notification Format 

All CBSAPI notifications are published in one of two formats:

* JSON 
* Google Protobufs (https://code.google.com/p/protobuf/)

The documentation below calls out in which format each notification type is published. 

## Notification Mechanisms

This document describes the underlying events published on the Carbon Black server message bus.  It is expected that these events will be consumed programmatically.

The Carbon Black server provides built-in mechanisms to expose these same events via syslog and e-mail.  The configuration of these alternate notification mechanisms is outside of the scope of this document.

## Notification Types

* Watchlist hit
  * Process Watchlist
  * Binary Watchlist
* Feed hit
    * Ingress
        * Process Ingress Feed Hit
        * Binary Ingress Feed Hit
    * Storage
        * Process Storage Feed Hit
        * Binary Storage Feed Hit
    * Query
        * Process Query Feed Hit
        * Binary Query Feed Hit

* New binary instance
  * First instance of any endpoint observing a particular binary
  * First instance of an endpoint observing a particular binary
  * First instance of a sensor group observing a particular binary
* Binary file upload complete
* Raw endpoint events

### Watchlist Hit  

There are two types of watchlists:

* Process Watchlists
* Binary Watchlists

On watchlist "hit" (match), an event is published.  The bulk of the contents of the event is pulled from the underlying process or binary document.  As such, the event fields are different between the two event types.

#### Process Watchlist Hit

Name: `watchlist.hit.process`

`watchlist.hit.process` is a JSON structure with the following entries: 

| name              | type   | description | 
| ----------------- | -------|-------------| 
| `cb_version`      | string | Carbon Black server version|
| `event_timestamp` | string | Timestamp when event was published|
| `watchlist_id`    | int32  | Identifier of the watchlist that matched|
| `watchlist_name`  | string | Name of watchlist that matched|
| `server_name`     | string | Name of the Carbon Black Server|
| `docs`            | list   | List of one or more matching process documents; see next table|

Each matching process document is a JSON structure with the following entries:

| name              | type   | description |
| ----------------- | ------ | ----------- |
| `childproc_count` | int32  | Total count of child processes created by this process|
| `cmdline`         | string | Process command line |
| `filemod_count`   | int32  | Total count of file modifications made by this process|
| `group`           | string | Sensor group this sensor was assigned to at time of process execution|
| `host_type`       | string | Type of the computer: server, workstation, domain controller|
| `hostname`        | string | Hostname of the computer on which the process executed (at time of execution)|
| `last_update`     | string | Last activity in this process is endpoint local time.  Example: 2014-02-04T16:23:22.547Z |
| `modload_count`   | int32  | Total count of module loads in this process.| 
| `netconn_count`   | int32  | Total count of network connections made and received by this process.|
| `os_type`         | string | Operating system type of the endpoint, e.g. Windows, Linux, Osx. |
| `parent_name`     | string | Name of the parent process. |
| `parent_md5`      | string | MD5 of the parent process. |
| `parent_pid`      | int32  | PID of parent process. |
| `parent_unique_id`| string | Parent process unique identifer. |
| `path`            | string | Full path to the executable file backing this process.|
| `process_md5`     | string | MD5 of the executable file backing this process.|
| `process_name`    | string | Filename of the executable backing this process.|
| `process_pid`     | int32  | PID of this process. |
| `regmod_count`    | int32  | total count of registry modifications made by this process.|
| `segment_id`      | int32  | For internal use|
| `sensor_id`       | int32  | Endpoint identifier.|
| `start`           | string | Start time of this process in endpoint local time. Example: 2014-02-04T16:23:22.516Z|
| `unique_id`       | string | Process unique Id|
| `username`        | string | User context in which the process executed.|

Example:

```
  {
    "server_name": "cb-enterprise-testing.local", 
    "docs": [
        {"process_md5": "a3ccfd0aa0b17fd23aa9fd0d84b86c05", 
         "sensor_id": 1, 
         "modload_count": 49, 
         "parent_unique_id": "00000001-0000-09e4-01cf-a5dee70168f2-00000001", 
         "cmdline": "\"c:\\users\\admin\\desktop\\putty.exe\" ", 
         "filemod_count": 0, 
         "id": "00000001-0000-afbc-01cf-b31b9e83777f", 
         "parent_name": "explorer.exe", 
         "parent_md5": "332feab1435662fc6c672e25beb37be3", 
         "group": "Default Group", 
         "hostname": "WIN8-TEST", 
         "last_update": "2014-08-08T15:15:47.544Z", 
         "start": "2014-08-08T15:15:42.193Z", 
         "regmod_count": 6, 
         "process_pid": 44988, 
         "username": "win8-test\\admin", 
         "process_name": "putty.exe", 
         "path": "c:\\users\\admin\\desktop\\putty.exe", 
         "netconn_count": 1, 
         "parent_pid": 2532, 
         "segment_id": 1, 
         "host_type": "workstation", 
         "os_type": "windows", 
         "childproc_count": 0, 
         "unique_id": "00000001-0000-afbc-01cf-b31b9e83777f-00000001"}
     ], 
     "event_timestamp": 1407362104.19, 
     "watchlist_id": 10, 
     "cb_version": "4.2.1.140808.1059", 
     "watchlist_name": "Tor Feed"
  }
```

#### Binary Watchlist Hit

Name: `watchlist.hit.binary`

`watchlist.hit.binary` is a JSON structure with the following entries: 

| name              | type   | description | 
| ----------------- | -------| -------------| 
| `cb_version`      | string | Carbon Black server version|
| `event_timestamp` | string | Timestamp when event was published|
| `watchlist_id`    | int32  | Identifier of the watchlist that matched|
| `watchlist_name`  | string | Name of watchlist that matched|
| `server_name`     | string | Name of the Carbon Black Server|
| `docs`            | list   | List of one or more matching process documents; see next table|

Each matching binary document is a JSON structure with the following entries:

| name                    | type   | description | 
| ----------------------- | -------| -------------| 
| `copied_mod_len`        | int32  | Number of bytes copied to server|
| `endpoint`              | string | Hostname and sensor ID of the first endpoint on which this binary was observed. |
| `group`                 | string | First sensor group on which this binary was observed|
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
| `os_type`               | string | Operating system type, e.g. Windows, Linux, Osx. |
| `server_added_timestamp`| string | The time this binary was first seen by the server.
| `timestamp`             | string | Time binary was first observed (in endpoint time)|
| `watchlists`            | list   | List of matching watchlists.|
| `file_version`          | string | File Version (Windows Only)|
| `product_name`          | string | Product Name (Windows Only)|
| `company_name`          | string | Company Name (Windows Only)|
| `internal_name`         | string | Internal Name (Windows Only)|
| `original_filename`     | string | Internal Original Filename (Windows Only)|
| `file_desc`             | string | File Description (Windows only)|
| `product_desc`          | string | Product Description (Windows only)|
| `product_version`       | string | Product Description (Windows only)|
| `comments`              | string | Comment String (Windows only)|
| `legal_copyright`       | string | Legal copyright string (Windows only)|
| `legal_trademark`       | string | Legal trademark string (Windows only)|
| `private_build`         | string | Private build string (Windows only)|

Example:

```
  {
    "server_name": "cb-enterprise-testing.local", 
    "docs": [
        {"digsig_result": "Signed", 
         "observed_filename": ["c:\\windows\\system32\\prncache.dll"], 
         "product_version": "6.1.7601.17514", 
         "signed": "Signed", 
         "digsig_sign_time": "2010-11-21T00:37:00Z", 
         "is_executable_image": false, 
         "orig_mod_len": 183808, 
         "is_64bit": true, 
         "digsig_publisher": "Microsoft Corporation", 
         "group": ["Default Group"], 
         "file_version": "6.1.7601.17514 (win7sp1_rtm.101119-1850)", 
         "company_name": "Microsoft Corporation", 
         "internal_name": "PrintCache", 
         "product_name": "Microsoft\u00ae Windows\u00ae Operating System", 
         "digsig_result_code": "0", 
         "timestamp": "2014-08-09T11:19:04.009Z", 
         "copied_mod_len": 183808, 
         "server_added_timestamp": "2014-08-09T11:19:04.009Z", 
         "md5": "A1CDE92DDC170D307DB3C5BAA348811B", 
         "endpoint": ["WIN8-TEST|1"], 
         "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.", 
         "original_filename": "PrnCache.dll", 
         "os_type": "Windows", 
         "file_desc": "Print UI Cache"}
     ], 
     "event_timestamp": 1407583203.5, 
     "watchlist_id": 10, 
     "cb_version": "4.2.1.140811.29", 
     "watchlist_name": "SRS Trust"
  }
```

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

### Feed Hit

There are three types of feed events:

* Ingress
* Storage
* Query

Ingress feed events are published as the matching endpoint data arrives from the sensor.  These ingress feed events therefore provide the earliest available notification of the endpoint activity.  Ingress events are published prior to updating the data to the backend data store (SOLR), and therefore it may be up to fifteen minutes before the data is discoverable via search.  The latency is partially dependent on the configured SOLR soft-commit (auto-commit) interval.

Storage feed events are published as the data is committed to the backend data store (SOLR).  As compared to ingress feed events, storage feed events happen later in time, but when all data is fully indexed and searchable via SOLR and therefore the CB client API. 

Query feed events are published when a query string provided by a query feed matches comitted data.

#### Ingress Feed Hit

##### Process Ingress Feed Hit

Name: `feed.ingress.hit.process`

`feed.ingress.hit.process` is a JSON structure with the following entries:

| name  | type     | description | 
| ----- | ---------|-------------| 
| `process_id`     | string      | CB process key.  See Notes. | 
| `report_id`      | string      | Identifier of the report which included the matching IOC.  See notes. |
| `ioc_type`       | string      | One of "md5", "dns", "ipv4" | 
| `ioc_value`      | string      | The matching IOC. |
| `ioc_attr`       | JSON        | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32       | Sensor Id of the endpoint on which the event matching the feed occurred. |
| `hostname`       | string      | Hostname of the endpoint on which the event matching the feed occurred |
| `cb_version`     | string      | Carbon Black server version. |
| `server_name`    | string      | Name of Carbon Black server. |
| `feed_id`        | int32       | Identifier of the feed that included the matching report.  See notes. | 
| `feed_name`      | string      | The  name of the feed that included the matching report. | 
| `event_timestamp`| float       | Timestamp of the feed match, measured in number of seconds since the epoch |

Example Event:

```
  {
    "process_id":"00000001-0000-afbc-01cf-b31b9e83777f",
    "report_id":"TOR-Node-38.229.70.52",
    "ioc_type":"ipv4",
    "ioc_value":"38.229.70.52",
    "ioc_attr":{"port":22,"protocol":"TCP","direction":"Outbound"},
    "hostname":"FS-NYC-1",
    "sensor_id":1,
    "cb_version":"4.2.1.140808.1059",
    "server_name":"localhost.localdomain",
    "feed_id":14,
    "feed_name":"tor",
    "event_timestamp":1407362000
  }
```
Notes:

* The process_id field is the process key used to uniquely identify a process on the Carbon Black server.  For ingress feed hits, the process segment is not known.  The key can be used with the Carbon Black client API to query for the entire process document.

##### Binary Ingress Feed Hit

Name: `feed.ingress.hit.binary`

`feed.ingress.hit.binary` is a JSON structure with the following entries:

| name             | type      | description | 
| ---------------- | ----------|-------------| 
| `md5`            | string    | MD5 of the binary.| 
| `report_id`      | string    | Identifier of the report which included the matching IOC.|
| `ioc_type`       | string    | One of "md5", "dns", "ipv4" | 
| `ioc_value`      | string    | The matching IOC. |
| `ioc_attr`       | JSON      | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32     | Sensor Id of the endpoint on which the event matching the feed occurred|
| `hostname`       | string    | Hostname of the endpoint on which the event matching the feed occurred|
| `cb_version`     | string    | Carbon Black server version. |
| `server_name`    | string    | Name of Carbon Black server. |
| `feed_id`        | int32     | Identifier of the feed that included the matching report.| 
| `feed_name`      | string    | The  name of the feed that included the matching report.| 
| `event_timestamp`| float     | Timestamp of the feed match, measured in number of seconds since the epoch| 

Example Event:

```
    {
      "md5": "506708142BC63DABA64F2D3AD1DCD5BF",
      "report_id": "dxmtest1_04",
      "ioc_type": "md5",
      "ioc_value":"506708142bc63daba64f2d3ad1dcd5bf",
      "ioc_attr": {},
      "feed_id":7,
      "hostname": "FS-SEA-529",
      "sensor_id": 3321,
      "cb_version":"4.2.1.140808.1059",
      "server_name":"localhost.localdomain",
      "feed_name": "dxmtest1",
      "event_timestamp": 1397244093.682
    }
```

Notes:

* It may be as much as 60 seconds from the time of the event generation until the full binary document is queryable via the CBAPI or raw SOLR. 

#### Storage Feed Hit

##### Process Storage Feed Hit

Name: `feed.storage.hit.process`

`feed.storage.hit.process` is a JSON structure with the following entries:

| name             | type     | description | 
| -----------------| ---------|-------------| 
| `process_id`     | string   | CB process key.  See Notes.| 
| `segment_id`     | int32    | Process segment identifier.  See Notes.|
| `report_id`      | string   | Identifier of the report which included the matching IOC.  See notes. |
| `ioc_type`       | string   | One of "md5", "dns", "ipv4" | 
| `ioc_value`      | string   | The matching IOC. | 
| `ioc_attr`       | JSON     | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32    | Sensor Id of the endpoint on which the event matching the feed occurred |
| `hostname`       | string   | Hostname of the endpoint on which the event matching the feed occurred |
| `cb_version`     | string   | Carbon Black server version. |
| `server_name`    | string   | Name of Carbon Black server. |
| `feed_id`        | int32    | Identifier of the feed that included the matching report.  See notes. | 
| `feed_name`      | string   | The  name of the feed that included the matching report. | 
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch |
| `docs`           | list     | List of one or more matching process documents; see next table |

Each matching process document is a JSON structure with the following entries:

| name              | type   | description |
| ----------------- | ------ | ----------- |
| `childproc_count` | int32  | Total count of child processes created by this process |
| `cmdline`         | string | Process command line |
| `filemod_count`   | int32  | Total count of file modifications made by this process|
| `group`           | string | Sensor group this sensor was assigned to at time of process execution|
| `host_type`       | string | Type of the computer: server, workstation, domain controller|
| `last_update`     | string | Last activity in this process is endpoint local time.  Example: 2014-02-04T16:23:22.547Z |
| `modload_count`   | int32  | Total count of module loads in this process.| 
| `netconn_count`   | int32  | Total count of network connections made and received by this process.|
| `os_type`         | string | Operating system type, e.g. Windows, Linux, Osx. |
| `parent_name`     | string | Name of the parent process. |
| `parent_md5`      | string | MD5 of the parent process. |
| `parent_pid`      | int32  | PID of parent process. |
| `parent_unique_id`| string | Parent process unique identifer. |
| `path`            | string | Full path to the executable file backing this process.|
| `process_md5`     | string | MD5 of the executable file backing this process.|
| `process_name`    | string | Filename of the executable backing this process.|
| `process_pid`     | int32  | PID of this process. |
| `regmod_count`    | int32  | total count of registry modifications made by this process.|
| `segment_id`      | int32  | For internal use|
| `start`           | string | Start time of this process in endpoint local time. Example: 2014-02-04T16:23:22.516Z|
| `unique_id`       | string | Process unique Id|
| `username`        | string | User context in which the process executed.|


Example Event:

```
  {
    "process_id":"00000001-0000-afbc-01cf-b31b9e83777f",
    "segment_id":1,
    "docs":[
        {"modload_count":0,
         "host_type":"workstation",
         "netconn_count":"1",
         "os_type":"windows",
         "unique_id":"00000001-0000-afbc-01cf-b31b9e83777f-00000001",
         "username":"win8-test\\admin",
         "last_update":"2014-08-08T15:15:47.544Z",
         "parent_md5":"332feab1435662fc6c672e25beb37be3",
         "path":"c:\\users\\admin\\desktop\\putty.exe",
         "filemod_count":0,
         "regmod_count":6,
         "process_name":"putty.exe",
         "cmdline":"\"c:\\users\\admin\\desktop\\putty.exe\" ",
         "parent_unique_id":"00000001-0000-09e4-01cf-a5dee70168f2-00000001",
         "childproc_count":0,
         "process_pid":"44988",
         "start":"2014-08-08T15:15:42.193Z",
         "process_md5":"a3ccfd0aa0b17fd23aa9fd0d84b86c05",
         "parent_name":"explorer.exe",
         "parent_pid":"2532",
         "group":"Default Group"}
     ],
     "report_id":"TOR-Node-38.229.70.52",
     "ioc_type":"ipv4",
     "ioc_value":"38.229.70.52",
     "ioc_attr":{"port":"22","protocol":"TCP","direction":"Outbound"},
     "hostname":"WIN8-TEST",
     "sensor_id":1,
     "cb_version":"4.2.1.140808.1059",
     "server_name":"localhost",
     "feed_id":14,
     "feed_name":"tor",
     "event_timestamp":1407362099.567
  }
```

Notes:

* The process_id and segment_id fields can be used to construct a request for complete process segment information, including events such as netconns, modloads, and similar, using the Carbon Black Client API.

##### Binary Storage Feed Hit 

Name: `feed.storage.hit.binary`

`feed.storage.hit.binary` is a JSON structure with the following entries:

| name             | type     | description | 
| -----------------|----------|-------------| 
| `md5`            | string   | MD5 of the binary. | 
| `report_id`      | string   | Identifier of the report which included the matching IOC. |
| `ioc_type`       | string   | One of "md5", "dns", "ipv4" | 
| `ioc_value`      | string   | The matching IOC. |
| `ioc_attr`       | JSON     | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32    | Sensor Id of the endpoint on which the event matching the feed occurred |
| `hostname`       | string   | Hostname of the endpoint on which the event matching the feed occurred |
| `cb_version`     | string   | Carbon Black server version. |
| `server_name`    | string   | Name of Carbon Black server. |
| `feed_id`        | int32    | Identifier of the feed that included the matching report. | 
| `feed_name`      | string   | The  name of the feed that included the matching report. | 
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch | 
| `docs`           | list     | List of one or more matching process documents; see next table |

Each matching process document is a JSON structure with the following entries:

  
| name                    | type   | description | 
| ----------------------- | -------| -------------| 
| `copied_mod_len`        | int32  | Number of bytes copied to server|
| `endpoint`              | string | Hostname and sensor ID of the endpoint on which this binary was observed. |
| `group`                 | string | First sensor group on which this binary was observed|
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
| `os_type`               | string | Operating system type of the endpoint, e.g. Windows, Linux, Osx. |
| `server_added_timestamp`| string | The time this binary was first seen by the server.
| `file_version`          | string | File Version (Windows Only)|
| `product_name`          | string | Product Name (Windows Only)|
| `company_name`          | string | Company Name (Windows Only)|
| `internal_name`         | string | Internal Name (Windows Only)|
| `original_filename`     | string | Internal Original Filename (Windows Only)|
| `file_desc`             | string | File Description (Windows only)|
| `product_desc`          | string | Product Description (Windows only)|
| `product_version`       | string | Product Description (Windows only)|
| `comments`              | string | Comment String (Windows only)|
| `legal_copyright`       | string | Legal copyright string (Windows only)|
| `legal_trademarkt`      | string | Legal trademark string (Windows only)|
| `private_build`         | string | Private build string (Windows only)|


Example Event:

```
  {
    "md5":"C3489639EC8E181044F6C6BFD3D01AC9",
    "docs":[
        {"file_version":"6.1.7601.17514 (win7sp1_rtm.101119-1850)",
        "product_name":"Microsoft Windows Operating System",
        "is_executable_image":"false",
        "digsig_result":"Signed",
        "observed_filename":["c:\\windows\\system32\\sndvol.exe","C:\\Windows\\system32\\sndvol.exe"],
        "os_type":"Windows",
        "orig_mod_len":"273920",
        "company_name":"Microsoft Corporation",
        "server_added_timestamp":"Aug 9, 2014 5:27:56 PM",
        "internal_name":"Volume Control Applet",
        "copied_mod_len":"0",
        "product_version":"6.1.7601.17514",
        "digsig_sign_time":"2010-11-21T00:37:00.000Z",
        "alliance_score_srstrust":"-100",
        "digsig_result_code":"0",
        "file_desc":"Volume Mixer",
        "endpoint":"WIN8-TEST|1",
        "legal_copyright":"Microsoft Corporation. All rights reserved.",
        "original_filename":"SndVol.exe",
        "is_64bit":"true",
        "md5":"C3489639EC8E181044F6C6BFD3D01AC9",
        "digsig_publisher":"Microsoft Corporation",
        "group":"Default Group"}
    ],
    "report_id":"c3489639ec8e181044f6c6bfd3d01ac9",
    "ioc_type":"md5",
    "ioc_value":"c3489639ec8e181044f6c6bfd3d01ac9",
    "ioc_attr":{},
    "hostname":"WIN8-TEST",
    "sensor_id":1,
    "cb_version":"4.2.1.140811.1054",
    "server_name":"localhost",
    "feed_id":2,
    "feed_name":"srstrust",
    "event_timestamp":1407621575.945
  }
```

Notes: It can be up to 15 seconds from the time of the event generation until the document is visible via CBAPI or raw SOLR query.

#### Query Feed Hit

##### Process Query Feed Hit

Name: `feed.query.hit.process`

`feed.query.hit.process` is a JSON structure with the following entries:

| name             | type     | description | 
| -----------------| ---------|-------------| 
| `process_id`     | string   | CB process key.  See Notes.| 
| `sensor_id`      | string   | Always 0 for event. See process document for matching values. | 
| `segment_id`     | int32    | Process segment identifier.  See Notes.|
| `report_id`      | string   | Identifier of the report which included the matching IOC.  See notes. |
| `ioc_type`       | string   | Always the value "query" | 
| `ioc_value`      | string   | The query string used to look for matches | 
| `ioc_attr`       | JSON     | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32    | Sensor Id of the endpoint on which the event matching the feed occurred |
| `hostname`       | string   | Hostname of the endpoint on which the event matching the feed occurred |
| `cb_version`     | string   | Carbon Black server version. |
| `server_name`    | string   | Name of Carbon Black server. |
| `feed_id`        | int32    | Identifier of the feed that included the matching report.  See notes. | 
| `feed_name`      | string   | The  name of the feed that included the matching report. | 
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch |
| `docs`           | list     | List of one or more matching process documents; see next table |

Each matching process document is a JSON structure with the following entries:

| name              | type   | description |
| ----------------- | ------ | ----------- |
| `childproc_count` | int32  | Total count of child processes created by this process |
| `cmdline`         | string | Process command line |
| `filemod_count`   | int32  | Total count of file modifications made by this process|
| `group`           | string | Sensor group this sensor was assigned to at time of process execution|
| `host_type`       | string | Type of the computer: server, workstation, domain controller|
| `hostname`        | string | Hostname of the endpoint on which the event matching the feed occurred |
| `last_update`     | string | Last activity in this process is endpoint local time.  Example: 2014-02-04T16:23:22.547Z |
| `modload_count`   | int32  | Total count of module loads in this process.| 
| `netconn_count`   | int32  | Total count of network connections made and received by this process.|
| `os_type`         | string | Operating system type, e.g. Windows, Linux, Osx. |
| `parent_name`     | string | Name of the parent process. |
| `parent_md5`      | string | MD5 of the parent process. |
| `parent_pid`      | int32  | PID of parent process. |
| `parent_unique_id`| string | Parent process unique identifer. |
| `path`            | string | Full path to the executable file backing this process.|
| `process_md5`     | string | MD5 of the executable file backing this process.|
| `process_name`    | string | Filename of the executable backing this process.|
| `process_pid`     | int32  | PID of this process. |
| `regmod_count`    | int32  | total count of registry modifications made by this process.|
| `segment_id`      | int32  | For internal use|
| `sensor_id`       | int32  | Endpoint identifier.|
| `start`           | string | Start time of this process in endpoint local time. Example: 2014-02-04T16:23:22.516Z|
| `unique_id`       | string | Process unique Id|
| `username`        | string | User context in which the process executed.|


Example Event:

```
{
  "process_id": "00000001-0000-1098-01cf-cc5fea563f8f",
  "sensor_id": 1,
  "segment_id": 1,
  "docs": [
    {
      "username": "WIN7X64-BUILDER\\User",
      "process_md5": "f2c7bb8acc97f92e987a2d4087d021b1",
      "modload_count": 20,
      "parent_unique_id": "00000001-0000-0a84-01cf-c240c9d1f378-00000001",
      "process_name": "notepad.exe",
      "cmdline": "\"c:\\windows\\system32\\notepad.exe\" ",
      "os_type": "windows",
      "path": "c:\\windows\\system32\\notepad.exe",
      "last_update": "2014-09-09T18:57:34.267Z",
      "parent_pid": 2692,
      "crossproc_count": 0,
      "parent_name": "explorer.exe",
      "parent_md5": "000000000000000000000000000000",
      "group": "Default Group",
      "netconn_count": 0,
      "hostname": "WIN7X64-BUILDER",
      "host_type": "workstation",
      "filemod_count": 0,
      "start": "2014-09-09T18:57:34.251Z",
      "unique_id": "00000001-0000-1098-01cf-cc5fea563f8f-00000001",
      "regmod_count": 0,
      "childproc_count": 0,
      "process_pid": 4248
    }
  ],
  "hostname": "DXM021-VM1",
  "event_timestamp": 1410289221.38,
  "feed_name": "dxmtest2",
  "feed_id": 12,
  "ioc_value": "cb.urlver=1&cb.q.process_name=notepad.exe&sort=start%20desc&rows=10&start=0",
  "ioc_type": "query",
  "ioc_attrs": {
    "highlights": [
      "PREPREPREnotepad.exePOSTPOSTPOST",
      "c:\\windows\\system32\\PREPREPREnotepad.exePOSTPOSTPOST"
    ]
  },
  "report_id": "notepad_proc"
}
```

Notes:

* The process_id and segment_id fields can be used to construct a request for complete process segment information, including events such as netconns, modloads, and similar, using the Carbon Black Client API.

##### Binary Storage Feed Hit 

Name: `feed.storage.hit.binary`

`feed.storage.hit.binary` is a JSON structure with the following entries:

| name             | type     | description | 
| -----------------|----------|-------------| 
| `md5`            | string   | MD5 of the binary. | 
| `report_id`      | string   | Identifier of the report which included the matching IOC. |
| `ioc_type`       | string   | Always the value "query" | 
| `ioc_value`      | string   | The query string used to look for matches | 
| `ioc_attr`       | JSON     | Key value pairs of additional attributes related to the hit (if present). |
| `sensor_id`      | int32    | Sensor Id of the endpoint on which the event matching the feed occurred |
| `hostname`       | string   | Hostname of the endpoint on which the event matching the feed occurred |
| `cb_version`     | string   | Carbon Black server version. |
| `server_name`    | string   | Name of Carbon Black server. |
| `feed_id`        | int32    | Identifier of the feed that included the matching report. | 
| `feed_name`      | string   | The  name of the feed that included the matching report. | 
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch | 
| `docs`           | list     | List of one or more matching process documents; see next table |

Each matching process document is a JSON structure with the following entries:

  
| name                    | type   | description | 
| ----------------------- | -------| -------------| 
| `comments`              | string | Comment String (Windows only)|
| `company_name`          | string | Company Name (Windows Only)|
| `copied_mod_len`        | int32  | Number of bytes copied to server|
| `endpoint`              | string | Hostname and sensor ID of the endpoint on which this binary was observed. |
| `file_desc`             | string | File Description (Windows only)|
| `file_version`          | string | File Version (Windows Only)|
| `group`                 | string | First sensor group on which this binary was observed|
| `host_count`            | int32  | Number of hosts containing this file|
| `digsig_issuer`         | string | If digitally signed, the issuer.|
| `digsig_publisher`      | string | If digitally signed, the publisher.|
| `digsig_result`         | string | If digitally signed, the human-readable status. See notes.|
| `digsig_result_code`    | in32   | For internal use.|
| `digsig_sign_time`      | string | If digitally signed, the sign time.|
| `digsig_subject`        | string | If digitally signed, the subject.|
| `internal_name`         | string | Internal Name (Windows Only)|
| `is_executable_image`   | bool   | True if the binary is a standalone executable (as compared to a library).|
| `is_64bit`              | bool   | True if architecture is x64 (versus x86)
| `last_seen`             | string | Time last seen|
| `legal_copyright`       | string | Legal copyright string (Windows only)|
| `legal_trademark`       | string | Legal trademark string (Windows only)|
| `md5`                   | string | MD5 of the binary|
| `observed_filename`     | string | Full path to the executable backing the process|
| `orig_mod_len`          | int32  | Size in bytes of the binary at the time of observation on the endpoint.|
| `original_filename`     | string | Internal Original Filename (Windows Only)|
| `os_type`               | string | Operating system type of the endpoint, e.g. Windows, Linux, Osx. |
| `private_build`         | string | Private build string (Windows only)|
| `product_desc`          | string | Product Description (Windows only)|
| `product_name`          | string | Product Name (Windows Only)|
| `product_version`       | string | Product Description (Windows only)|
| `server_added_timestamp`| string | The time this binary was first seen by the server.
| `signed`                | string | If digitally signed|
| `timestamp`             | string | The time this binary was first seen by the server.|

Example Event:

```
{
  "sensor_id": 1,
  "docs": [
    {
      "host_count": 1,
      "digsig_result": "Unsigned",
      "observed_filename": [
        "c:\\program files (x86)\\programmer's notepad\\pn.exe"
      ],
      "product_version": "2.3.4.0-charles",
      "signed": "Unsigned",
      "is_executable_image": false,
      "orig_mod_len": 3092992,
      "is_64bit": false,
      "group": [
        "Default Group"
      ],
      "file_version": "2.3.4.0",
      "company_name": "Simon Steele (Echo Software)",
      "internal_name": "PNWTL",
      "product_name": "Programmer's Notepad",
      "digsig_result_code": "2148204800",
      "timestamp": "2014-09-09T21:00:29.875Z",
      "copied_mod_len": 3092992,
      "server_added_timestamp": "2014-09-09T21:00:29.875Z",
      "md5": "EFA7ECAF4468E0106E8B1041C5CE450E",
      "endpoint": [
        "WIN7X64-BUILDER|1"
      ],
      "legal_copyright": "Copyright \u00a9 2002-2010 Simon Steele (Echo Software)",
      "original_filename": "pn.exe",
      "os_type": "Windows",
      "file_desc": "Programmer's Notepad 2",
      "last_seen": "2014-09-09T21:00:29.875Z"
    }
  ],
  "hostname": "DXM021-VM1",
  "event_timestamp": 1410296635.26,
  "feed_name": "dxmtest2",
  "feed_id": 12,
  "ioc_value": "cb.urlver=1&cb.q.process_name=notepad.exe&sort=start%20desc&rows=10&start=0",
  "ioc_type": "query",
  "md5": "EFA7ECAF4468E0106E8B1041C5CE450E",
  "report_id": "Newly Loaded Modules"
}
```

Notes: It can be up to 15 seconds from the time of the event generation until the document is visible via CBAPI or raw SOLR query.


### New Binary Instance

The Carbon Black server publishes events the first time an executable file (binary) is observed in each of three scenarios:

1. First time it is observed on *any* endpoint
2. First time it is observed on an *individual* endpoint for the first time
3. First time it is observed on a sensor group for the first time

#### Scenario 1: Observed for the first time on any endpoint

Name: `binaryinfo.observed`

`binaryinfo.observed` is a JSON structure with the following entries:

| name             | type     | description | 
| ---------------- | -------- |-------------| 
| `md5`            | string   | MD5 of the binary|
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch| 
| `scores`         | dict     | Dictionary of Alliance feed scores|

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "event_timestamp": 1397248033.914,
    "scores": 
      {
        "alliance_score_virustotal": 16
      }
}
```

#### Scenario 2: Observed on an individual endpoint for the first time

Name: `binaryinfo.host.observed`

`binaryinfo.host.observed` is a JSON structure with the following entries:

| name             | type     | description | 
| ---------------- | -------- | ----------- | 
| `md5`            | string   | MD5 of the binary.|
| `hostname`       | string   | Hostname of endpoint on which binary was observed|
| `sensor_id`      | int32    | Sensor Id of endpoint on which binary was observed|
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch| 
| `scores`         | dict     | Dictionary of Alliance feed scores|
| `watchlists`     | dict     | Dictionary of already-matched watchlists|

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "hostname": "FS-HQ",
    "sensor_id": 1021,
    "event_timestamp": 1397248033.914,
    "scores": 
      {
        "alliance_score_virustotal": 16
      },
    "watchlists":
      {
        "watchlist_7": "2014-02-13T00:30:11.247Z"
        "watchlist_9": "2014-02-13T00:21:13.009Z"
      }
}
```

##### Scenario 3: Observed within a sensor group for the first time

Name: `binaryinfo.group.observed`

`binaryinfo.group.observed` is a JSON structure with the following entries:

| name             | type     | description | 
| ---------------- | -------- |-------------| 
| `md5`            | string   | MD5 of the binary|
| `group`          | string   | Sensor group name on which the binary was observed|
| `event_timestamp`| float    | Timestamp of the feed match, measured in number of seconds since the epoch| 
| `scores`         | dict     | Dictionary of Alliance feed scores|
| `watchlists`     | dict     | Dictionary of already-matched watchlists|

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "group": "Default Group",
    "event_timestamp": 1397248033.914
    "scores": 
      {
        "alliance_score_virustotal": 16
      },
    "watchlists":
      {
        "watchlist_7": "2014-02-13T00:30:11.247Z"
        "watchlist_9": "2014-02-13T00:21:13.009Z"
      }
}
```

#### New Binary File Arrival

The Carbon Black server can be configured to store a copy of all unique binary (executable) files observed on endpoints.  This includes Windows PE files such as EXEs and DLLs, Linux ELF files, and similar.  Upon the arrival of a new binary file, a binarystore event is published.

This event provides an easy way to trigger custom analysis of a binary, including static or dynamic anaysis, integration with a third-party analysis system, or custom archiving.

Name: `binarystore.file.added`
 
`binarystore.file.added` is a JSON structure with the following entries:

| name             | type     | description | 
| -----------------|----------|-------------| 
| `md5`            | string   | MD5 sum of the binary file. | 
| `size`           | int32    | Size of the original binary, in bytes. |
| `compressed_size`| int32    | Size of the zip archive containing the binary file on the Carbon Black server | 
| `event_timestamp`| float    | Timestamp of the binary file addtion, measured in number of seconds since the epoch 
| `file_path`      | string   | Path, on the server disk, of the copied binary file (zipped).|

Example Event:

```
{
    "md5": "9E4B0E7472B4CEBA9E17F440B8CB0AB8",
    "file_path": "/var/cb/data/modulestore/FE2/AFA/FE2AFACC396DC37F51421DE4A08DA8A7.zip"
    "size": 320000,
    "compressed_size": 126857,
    "event_timestamp": 1397248033.914
}
```
Notes:

* The Carbon Black Server can be configured to delete binary store files from the Carbon Black server after uploading to the Alliance Server.  These files are still retrievable via the Carbon Black API, although there may be bandwidth or transfer time concerns.  See the `AllianceClientNoDeleteOnUpload` configuration option in `cb.conf`. 
* The Carbon Black Server can be configured to automatically delete binary store files from the Carbon Black server due to disk space constraints.  See the `KeepAllModuleFiles` configuration option in `cb.conf`.  

#### Raw Endpoint Events

The Carbon Black Server can be configured to publish some or all raw endpoint events as collected by the attached sensors.

These events are the raw endpoint events and are exported:

* upon arrival on the Carbon Black server
* prior to processing, storage, and indexing on the Carbon Black server.

The raw events themselves are published in Google Protobuffers format (https://code.google.com/p/protobuf/).  This is the same format used by the sensors themselves to encode the raw events. 

The raw event volume can easily be measured in tens of thousands per second.  The Carbon Black server can be configured to export only specific event types in order to reduce the performance impact of event export.

##### Raw Endpoint Event Types

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

##### Configuring the Carbon Black server to export raw endpoint events

The Carbon Black server can be configured to export some or all raw endpoint events by modifying cb.conf, found at `/etc/cb/cb.conf`. 

In particular, the following configuration option:

    DatastoreBroadcastEventTypes=<TYPE[S]>

The supported types are:

| type         | description | 
| -------------|-------------| 
| *            | all endpoint events|
| moduleload   | Binary module loads (for example, DLLs on Windows)|
| netconn      | Network connections|
| filemod      | File modifications|
| regmod       | Registry modifications|
| process      | Process creation and termination|
| moduleinfo   | Binary module information|

Multiple types can be specified using a comma delimiter, without spaces.

##### Google Protocol Buffers definition

The Google Protocol Buffers definition for all raw endpoint events is found at:

    proto/sensor_events.proto
    

##### Subscribing to raw endpoint events

(1) Update cb.conf as per the above instructions. 
(2) Restart cb-enterprise:

    service cb-enterprise restart

(3) Subscribe to the events programmatically.  See the example below for one means to do that.

##### Example

[root@localhost example]# python subscribe_all.py -p OxU4Nwyf5DE7UNrA

-> Subscribed!


