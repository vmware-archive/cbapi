Carbon Black Enterprise Server Client API 
=========================

https://www.bit9.com/solutions/carbon-black/

## REST API

### Client Bindings

The Carbon Black API is a RESTful API.  This means that the API can be consumed by practically any language.

Example client bindings and scripts are included for reference purposes.  Both the bindings and example scripts
are implemented in python and C#.

The core client bindings can be found at:
* python (client_apis/python/src/cbapi/cbapi.py
* c# (client_apis/csharp/src/Bit9CarbonBlack.CarbonBlack.Client/CbClient.cs)

#### Note on Dependencies

For the Python client bindings, HTTP communication is supported via the python requests library.  The client bindings require version 1.0.0 of the requests libarary, released 12-17-2012.  Previous versions of the requests library are not compatible with cbapi as written.

### Versioned 

The following APIs are versioned. 

#### Process Data 
- [`/api/v1/process`](#apiv1process) - Process search
- [`/api/v1/process/(id)/(segment)`](#apiv1processidsegment) - Process summary data
- [`/api/v1/process/(id)/(segment)/event`](#apiv1processidsegmentevent) - Events for the selected process
- [`/api/v1/process/(id)/(segment)/preview`](#apiv1processidsegmentpreviewqquery) - Preview for the selected process

#### Binary Data
- [`/api/v1/binary`](#apiv1binary) - Binary search
- [`/api/v1/binary/(md5)`](#apiv1binarymd5) - Download the binary
- [`/api/v1/binary/(md5)/icon`](#apiv1binarymd5icon) - Icon of the binary (in PNG format) 
- [`/api/v1/binary/(md5)/summary`](#apiv1binarymd5summary) - Binary metadata
 
#### Sensors & Sensor Groups 
- [`/api/v1/sensor`](#apiv1sensoridhostnamehostnameipipaddr) - Sensor details
- [`/api/v1/group/<groupid>/installer/windows/exe`](#windowsexeinstaller) - Signed EXE Sensor Installer for Windows
- [`/api/v1/group/<groupid>/installer/windows/msi`](#windowsmsiinstaller) - Signed MSI Sensor Installer for Windows
- [`/api/v1/group/<groupid>/installer/osx`](#osxinstaller) - PKG Sensor Installer for OSX
- [`/api/v1/group/<groupid>/installer/linux`](#linuxinstaller) - Sensor Installer for Linux
- [`/api/v1/sensor/statistics`](#sensorstatistics) - Global sensor status, including aggregate sensor data backlog

#### Watchlists
- [`/api/v1/watchlist`](#apiv1watchlist) - Watchlist enumeration, addition, modification, and deletion

#### Feeds
- [`/api/v1/feed`](#apiv1feed) - Feed enumeration, addition, modification, and deletion

#### Licensing
- [`/api/v1/license`](#apiv1license) - Server license status, requests, and application of new license

#### Server Configuration
- [`/api/v1/settings/global/platformserver`](#apiv1settingsglobalplatformserver) - Bit9 Platform Server Integration Configuration

### Beta

The following APIs are beta.  Backwards compatibility will not be supported.  Contents are not expected to widely change.

- `/api/info` - top-level configuration

## API Authentication

Each user in Cb has a personal API key.   To find a API key corresponding with a particular Carbon Black user account, log into the console as that user, then click the username in the upper right -> Profile -> API Token.   (If the API Token is missing or otherwise compromised, click "Reset" to generate a new token for that user.)

For an API request to the Cb server, add this key to a custom HTTP Request Header `X-Auth-Token`.

For example, to get the summary information for a binary with MD5 6D778E0F95447E6546553EEEA709D03C:

```
[root@localhost flask]# curl -H 'X-Auth-Token:15dd7c486d81899f64643d6618c47a4e5ccc5c01' http://127.0.0.1/api/v1/binary/6D778E0F95447E6546553EEEA709D03C/summary
{
  "digsig_result": "Signed",
  "observed_filename": [
    "c:\\windows\\system32\\cmd.exe"
  ],
  "product_version": "5.1.2600.5512",
  "signed": "Signed",
  "digsig_sign_time": "2008-04-14T09:07:00Z",
  "orig_mod_len": 389120,
  "is_executable_image": true,
  "is_64bit": false,
  "digsig_publisher": "Microsoft Corporation",
  "file_version": "5.1.2600.5512 (xpsp.080413-2111)",
  "company_name": "Microsoft Corporation",
  "internal_name": "cmd",
  "_version_": 1457126999526998016,
  "product_name": "Microsoft\u00c2\u00ae Windows\u00c2\u00ae Operating System",
  "digsig_result_code": "0",
  "timestamp": "2014-01-13T14:49:55.189Z",
  "copied_mod_len": 389120,
  "server_added_timestamp": "2014-01-13T14:49:55.189Z",
  "md5": "6D778E0F95447E6546553EEEA709D03C",
  "legal_copyright": "\u00c2\u00a9 Microsoft Corporation. All rights reserved.",
  "original_filename": "Cmd.Exe",
  "file_desc": "Windows Command Processor"
}
```

## API Reference

####  `/api/v1/process`
Process search.  Parameters passed as a query string.

*Supports*:: `GET`

##### Parameters:
- `q`: REQUIRED Query string. Accepts the same data as the search box on the Process Search page.  See https://github.com/carbonblack/cbapi/blob/master/client_apis/docs/query_overview.pdf 
- `rows`: OPTIONAL Return this many rows, 10 by default.
- `start`: OPTIONAL Start at this row, 0 by default.
- `sort`: OPTIONAL Sort rows by this field and order.  `last_update desc` by default.
- `facets`: OPTIONAL Return facet results.  'false' by default, set to 'true' for facets.

##### Returns:
JSON object with the following elements:

- `results`: a list of matching processes (see below for process object)
- `terms`: a list of strings, each representing a token as parsed by the query parser
- `total_results`: number of matching processes
- `start`: index of first row
- `elapsed`: clock time elapsed resolving this request  
- `events`: a list of event objects matching the query string (see below for event object)
- `facets`: a list of facet entries if requested. (see below for facet object)
- `tagged_pids`: a list of process IDs in this result set that have one or more events tagged as part of an investigation
- `filtered`: count of results filtered due to security settings

*Process Object*

A process contains the following fields:
- `process_md5`: the md5 of the binary image backing the process
- `process_name`: the name of the process
- `start`: the start time of the process in remote computer GMT time
- `last_update`: the time of the most recently received event for this process in remote computer GMT time
- `hostname`: the hostname of the computer for this process
- `modload_count`: the count of modules loaded in this process
- `regmod_count`: the count of registry modifications in this process
- `filemod_count`: the count of file modifications in this process
- `netconn_count`: count of network connections in this process
- `childproc_count`: the count of child processes launched by this process
- `group`: the CB Host group this sensor is assigned to 
- `sensor_id`: the internal CB id for the sensor on which the process executed
- `id`: the internal CB process GUID for this process (processes are identified by this GUID and their segment id)
- `segment_id`: the process segment id (processes are identified by this segment id and their process ID id)
- `unique_id`: internal CB process id combining of the process GUID and segment GUID
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

*Event Object*

An event object contains the following fields:
- `name`: the full value containing a match.  The matching substring is bracketed with PREPREPRE and POSTPOSTPOST
- `ids`: a list of process `unique_id`s containing `name`

*Facet Object*

The facet object is a list of dictionaries with the following keys.  Each key is a list of facet results objects that contain the top 200 name, value and percentage for the unique set of results matching the search.  

- `process_md5`: the top unique process_md5s for the processes matching the search
- `hostname`: the top unique hostnames matching the search
- `group`: the top unique host groups for hosts matching this search
- `path_full`: the top unique paths for the processes matching this search
- `parent_name`: the top unique parent process names for the processes matching this search
- `process_name`: the top unique process names for the processes matching this search
- `host_type`: the distribution of host types matching this search: one of workstation, server, domain_controller
- `hour_of_day`: the distribution of process start times by hour of day in computer local time
- `day_of_week`: the distribution of process start times by day of week in computer local time 
- `start`: the distribution of process start times by day for the last 30 days

Each facet result object has three values:
- `name`: the facet value
- `value`: the count of occurrences of this value
- `percent`: count / max(count) - the ratio of this value to the largest value in the result set
- `ratio`: count / sum(count) - the ratio of this value to the sum of all values in the result set

A complete example:

```
GET http://192.168.206.151/api/v1/process/?q=notepad.exe

{
  "results": [
    {
      "process_md5": "ac4c51eb24aa95b77f705ab159189e24", 
      "process_name": "explorer.exe", 
      "group": "Default Group", 
      "segment_id": 1, 
      "netconn_count": 0, 
      "hostname": "WIN-EP7RMLTCLAJ", 
      "last_update": "2013-08-22T15:00:02Z", 
      "start": "2013-08-14T13:41:57Z", 
      "sensor_id": 2, 
      "modload_count": 103, 
      "path": "c:\\windows\\explorer.exe", 
      "regmod_count": 355, 
      "filemod_count": 10, 
      "id": "-3748189368838069954", 
      "unique_id": "cbfbc1a0-b782-e13e-0000-000000000001", 
      "childproc_count": 7,
      "os_type: "windows"
    }, 
  ], 
  "terms": [
    "notepad.exe"
  ], 
  "total_results": 1, 
  "elapsed": 0.8763120174407959, 
  "start": 0, 
  "facets": {}, 
  "events": [
    {
      "name": "\\registry\\user\\s-1-5-21-2445116603-3509627529-3207332553-1000_classes\\local settings\\software\\microsoft\\windows\\shell\\muicache\\c:\\windows\\system32\\PREPREPREnotepad.exePOSTPOSTPOST", 
      "ids": [
        "cbfbc1a0-b782-e13e-0000-000000000001"
      ]
    }, 
  ]
  "tagged_pids": {  }, 
  "filtered": {}, 
}
```

-----
####  `/api/v1/process/(id)/(segment)`
Gets basic process information for segment (segment) of process (guid)

*Supports*: `GET`

##### Parameters:
- `id`: REQUIRED the internal CB process guid, the `id` field in search results
- `segment`: REQUIRED the process segment, the `segment_id` field in search results.

##### Returns:
A JSON object with the following structure:

- `process`: a process summary object with metadata for the selected process
- `siblings`: a list of process summary objects for the first 15 sibiling processes
- `children`: a list of process summary objects for each child process
- `parent`: a process summary object with metadata for the parent process

Each process summary object contains the following structure:

- `process_md5`: the MD5 of the executable backing this process 
- `sensor_id`: the sensor id of the host this process executed on
- `group`: the sensor group the sensor was assigned to
- `parent_id`: the process guid of the parent process
- `process_name`: the name of this process, e.g., svchost.exe
- `path`: the full path of the executable backing this process, e.g., c:\windows\system32\svchost.exe
- `last_update`: the time of the last event received from this process, as recorded by the remote host
- `start`: the start time of this process, as recorded by the remote host
- `hostname`: the hostname of the computer this process executed on
- `id`: the internal CB process guid of this process
- `segment_id`: the segment id of this process
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

A complete example:

```
GET http://192.168.206.154/api/v1/process/2032659773721368929/1

{
  "process": {
    "process_md5": "517110bd83835338c037269e603db55d", 
    "sensor_id": 2, 
    "group": "Default Group", 
    "start": "2013-09-19T22:07:07Z", 
    "process_name": "taskhost.exe", 
    "segment_id": 1, 
    "last_update": "2013-09-19T22:09:07Z", 
    "cmdline": "taskhost.exe $(arg0)", 
    "hostname": "WIN-EP7RMLTCLAJ", 
    "parent_id": "5856845119039539348", 
    "path": "c:\\windows\\system32\\taskhost.exe", 
    "id": "2032659773721368929",
    "os_type": "windows"
  }, 
  "siblings": [
    {
      "process_md5": "c78655bc80301d76ed4fef1c1ea40a7d", 
      "sensor_id": 2, 
      "group": "Default Group", 
      "parent_id": "5856845119039539348", 
      "process_name": "svchost.exe", 
      "segment_id": 1, 
      "last_update": "2013-09-19T22:34:49Z", 
      "start": "2013-09-10T04:10:07Z", 
      "hostname": "WIN-EP7RMLTCLAJ", 
      "path": "c:\\windows\\system32\\svchost.exe", 
      "id": "5286285292765095481",
      "os_type": "windows"
    }, 
  ], 
  "children": [], 
  "parent": {
    "process_md5": "24acb7e5be595468e3b9aa488b9b4fcb", 
    "sensor_id": 2, 
    "group": "Default Group", 
    "parent_id": "4245649408199694328", 
    "process_name": "services.exe", 
    "segment_id": 1, 
    "last_update": "2013-09-19T22:09:07Z", 
    "start": "2013-09-10T04:09:51Z", 
    "hostname": "WIN-EP7RMLTCLAJ", 
    "path": "c:\\windows\\system32\\services.exe", 
    "id": "5856845119039539348",
    "os_type": "windows"
  }
}
```
-----
#### `/api/v1/process/(id)/(segment)/event`
Gets the events for the process with id (id) and segment (segment)

*Supports*:: `GET`

##### Parameters
- `id`: REQUIRED the internal CB process guid, the `id` field in search results
- `segment`: REQUIRED the process segment, the `segment_id` field in search results.


##### Returns:
A JSON object with the following structure:

- `process`: a process summary object with metadata and events for the selected process
- `elapsed`: the clock time required to get this structure
 
The process object may contain the following entries.

- `process_md5`: the MD5 of the executable backing this process 
- `sensor_id`: the sensor id of the host this process executed on
- `group`: the sensor group the sensor was assigned to
- `parent_id`: the process guid of the parent process
- `process_name`: the name of this process, e.g., svchost.exe
- `path`: the full path of the executable backing this process, e.g., c:\windows\system32\svchost.exe
- `cmdline`: the command line of the process
- `last_update`: the time of the last event received from this process, as recorded by the remote host
- `start`: the start time of this process, as recorded by the remote host
- `hostname`: the hostname of the computer this process executed on
- `id`: the internal CB process guid of this process
- `segment_id`: the segment id of this process
- `regmod_complete`: a pipe-delimited list of regmod strings
- `filemod_complete`: a pipe-delimited list of filemod strings
- `modload_complete`: a pipe-delimited list of modload strings
- `netconn_complete`: a pipe-delimited list of netconn strings
- `childproc_complete`: a pipe-delimited list of childproc strings
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

Each xxx_complete record is a string similar to:

```
2013-09-19 22:07:07.000000|f404e59db6a0f122ab26bf4f3e2fd0fa|c:\\windows\\system32\\dxgi.dll"
```

The pipe character (`|`) delimits the fields.  

##### filemod_complete
```
"1|2013-09-16 07:11:58.000000|c:\\documents and settings\\administrator\\local settings\\temp\\hsperfdata_administrator\\3704|"
```
- field 0: operation type, an integer 1, 2, 4 or 8
  - 1: Created the file
  - 2: First wrote to the file
  - 4: Deleted the file
  - 8: Last wrote to the file
- field 1: event time
- field 2: file path
- field 3: if operation type (field 0) is 8, last write, this value is the md5 of the file after the last write

##### modload_complete
```
2013-09-19 22:07:07.000000|f404e59db6a0f122ab26bf4f3e2fd0fa|c:\\windows\\system32\\dxgi.dll"
```
- field 0: event time
- field 1: MD5 of the loaded module
- field 2: Full path of the loaded module

##### regmod_complete
```
"2|2013-09-19 22:07:07.000000|\\registry\\user\\s-1-5-19\\software\\microsoft\\sqmclient\\reliability\\adaptivesqm\\manifestinfo\\version"
```
- field 0: operation type, an integer 1, 2, 4 or 8
  - 1: Created the registry key
  - 2: First wrote to the registry key
  - 4: Deleted the key 
  - 8: Deleted the value
- field 1: event time
- field 3: the registry key path
 
##### netconn_complete
```
"2013-09-16 07:11:59.000000|-1979811809|80|6|dl.javafx.com|true"
```
- field 0: event time
- field 1: remote IP address as a 32-bit signed long
- field 2: remote port
- field 3: protocol: 6 is TCP, 17 is UDP
- field 4: domain name associated with the IP address, from the client's perspective at the time of the network connection
- field 5: boolean "true" if the connection was outbound; "false" if the connection was inbound

A complete example:

```
GET http://192.168.206.154/api/v1/process/2032659773721368929/1/event

{"process": 
  {"process_md5": "517110bd83835338c037269e603db55d", 
  "sensor_id": 2, 
  "group": "Default Group", 
  "start": "2013-09-19T22:07:07Z",
  "process_name": "taskhost.exe", 
  "segment_id": 1,
  "os_type": "windows",
  "regmod_complete": [
        "2|2013-09-19 22:07:07.000000|\\registry\\user\\s-1-5-19\\software\\microsoft\\sqmclient\\reliability\\adaptivesqm\\manifestinfo\\version", 
        "2|2013-09-19 22:09:07.000000|\\registry\\machine\\software\\microsoft\\reliability analysis\\rac\\wmilasttime"
        ], 
  "parent_id": "5856845119039539348", 
  "cmdline": "taskhost.exe $(arg0)", 
  "filemod_complete": [
        "2|2013-09-19 22:07:07.000000|c:\\programdata\\microsoft\\rac\\statedata\\racmetadata.dat|", 
        "2|2013-09-19 22:07:07.000000|c:\\programdata\\microsoft\\rac\\temp\\sql4475.tmp|", 
        "2|2013-09-19 22:07:07.000000|c:\\programdata\\microsoft\\rac\\temp\\sql4486.tmp|", 
        "2|2013-09-19 22:09:07.000000|c:\\programdata\\microsoft\\rac\\statedata\\racwmidatabookmarks.dat|", 
        "2|2013-09-19 22:09:07.000000|c:\\programdata\\microsoft\\rac\\publisheddata\\racwmidatabase.sdf|", 
        "4|2013-09-19 22:09:07.000000|c:\\programdata\\microsoft\\rac\\temp\\sql4486.tmp|", 
        "2|2013-09-19 22:09:07.000000|c:\\programdata\\microsoft\\rac\\statedata\\racdatabase.sdf|", 
        "4|2013-09-19 22:09:07.000000|c:\\programdata\\microsoft\\rac\\temp\\sql4475.tmp|"
        ], 
  "hostname": "WIN-EP7RMLTCLAJ", 
  "modload_complete": [
        "2013-09-19 22:07:07.000000|517110bd83835338c037269e603db55d|c:\\windows\\system32\\taskhost.exe", 
        "2013-09-19 22:07:07.000000|3556d5a8bf2cc508bdab51dec38d7c61|c:\\windows\\system32\\ntdll.dll", 
        "2013-09-19 22:07:07.000000|7a6326d96d53048fdec542df23d875a0|c:\\windows\\system32\\kernel32.dll", 
        "2013-09-19 22:07:07.000000|9c75cb8b98610f0cd85d99bb5876308b|c:\\windows\\system32\\sqlcese30.dll", 
        "2013-09-19 22:07:07.000000|e5744d18c88737c6356d0a8d6d49d512|c:\\windows\\system32\\sqlceqp30.dll", 
        "2013-09-19 22:07:07.000000|021287c2050fd5db4a8b084e2c38139c|c:\\windows\\system32\\winsatapi.dll", 
        "2013-09-19 22:07:07.000000|f404e59db6a0f122ab26bf4f3e2fd0fa|c:\\windows\\system32\\dxgi.dll", 
        "2013-09-19 22:07:07.000000|da1b7075260f3872585bfcdd668c648b|c:\\windows\\system32\\dwmapi.dll", 
        "2013-09-19 22:07:07.000000|497bfeddaf3950dd909c3b0c5558a25d|c:\\windows\\winsxs\\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a\\gdiplus.dll", 
        "2013-09-19 22:07:07.000000|5d8e6c95156ed1f79a63d1eade6f9ed5|c:\\windows\\system32\\setupapi.dll", 
        "2013-09-19 22:07:07.000000|2a86e54b441ad41557f75dc5609b9793|c:\\windows\\system32\\sspicli.dll", 
        "2013-09-19 22:07:07.000000|d6f630c1fd7f436316093ae500363b19|c:\\windows\\system32\\xmllite.dll"
      ], 
  "path": "c:\\windows\\system32\\taskhost.exe", 
  "last_update": "2013-09-19T22:09:07Z", 
  "id": "2032659773721368929"
  }, 
  "elapsed": 0.0126001834869
}
```
-----
#### `/api/v1/process/(id)/(segment)/preview?q=(query)`
Process preview.  Requires id and segment id.

*Supports*: `GET`

##### Parameters: 
- `id`: REQUIRED the internal CB process guid, the `id` field in search results
- `segment`: REQUIRED the process segment, the `segment_id` field in search results.
- `query`: OPTIONAL a process query string.  If present, preview results will highlight matching terms
 
##### Returns: 

A process preview structure with the following fields:

- `process_md5`: the MD5 of the executable backing this process 
- `sensor_id`: the sensor id of the host this process executed on
- `group`: the sensor group the sensor was assigned to
- `process_name`: the name of this process, e.g., svchost.exe
- `path`: the full path of the executable backing this process, e.g., c:\windows\system32\svchost.exe
- `last_update`: the time of the last event received from this process, as recorded by the remote host
- `start`: the start time of this process, as recorded by the remote host
- `hostname`: the hostname of the computer this process executed on
- `id`: the internal CB process guid of this process
- `segment_id`: the segment id of this process
- `regmod_complete`: a pipe-delimited **summary** list of regmod strings (see spec above)
- `filemod_complete`: a pipe-delimited **summary** list of filemod strings (see spec above)
- `modload_complete`: a pipe-delimited **summary** list of modload strings (see spec above)
- `netconn_complete`: a pipe-delimited **summary** list of netconn strings (see spec above)
- `childproc_complete`: a pipe-delimited list of **summary** childproc strings (see spec above)
- `modload_count`: the **total** count of modules loaded in this process
- `regmod_count`: the **total** count of registry modifications in this process
- `filemod_count`: the **total** count of file modifications in this process
- `netconn_count`: **total** count of network connections in this process
- `childproc_count`: the **total** count of child processes launched by this process
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

If a query string is provided, the endpoint will highlight all matching strings.  Highlighted results will 
be surrounded with `PREPREPRE` and `POSTPOSTPOST` to designate the start and end of a matching substring.

Where the full process API endpoint will return all `xxx_complete` records in the process (possibly 10s of thousands),
the preview endpoint will have 10s of events for this process.  

A complete example:
```
GET http://192.168.206.132/api/v1/process/7078511340675742078/1/preview/?q=windows
{
  "parent_name": "", 
  "hostname": "J-8205A0C27A0C4", 
  "group": "Default Group", 
  "process_md5": "5e7f3968069d32b26af0d7af0ec5dd97", 
  "netconn_count": 1, 
  "process_name": "svchost.exe", 
  "last_update": "2013-10-07T15:07:09Z", 
  "cmdline": "\"c:\\docume~1\\admini~1\\locals~1\\temp\\rad17929.tmp\\svchost.exe\" ", 
  "start": "2013-10-07T15:07:09Z", 
  "sensor_id": 1, 
  "modload_count": 15, 
  "modload_complete": [
    "2013-10-07 15:07:09.000000|27d9ed8cb8b62d1e0a8e5ace6cf52e2f|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\ntdll.dll", 
    "2013-10-07 15:07:09.000000|c24b983d211c34da8fcc1ac38477971d|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\kernel32.dll", 
    "2013-10-07 15:07:09.000000|355edbb4d412b01f1740c17e3f50fa00|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\msvcrt.dll", 
    "2013-10-07 15:07:09.000000|bab489a5fe26f2d0c910cf7af7e4cf92|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\advapi32.dll", 
    "2013-10-07 15:07:09.000000|b979d9d1c8073da21a7f80345f306a1d|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\rpcrt4.dll", 
    "2013-10-07 15:07:09.000000|7459c16cc3ef4651cab7c9260e43fc58|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\secur32.dll", 
    "2013-10-07 15:07:09.000000|67156d5a9ac356dc99d7bccb388e3316|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\wsock32.dll", 
    "2013-10-07 15:07:09.000000|2ccc474eb85ceaa3e1fa1726580a3e5a|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\ws2_32.dll", 
    "2013-10-07 15:07:09.000000|9789e95e1d88eeb4b922bf3ea7779c28|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\ws2help.dll", 
    "2013-10-07 15:07:09.000000|b4138e99236f0f57d4cf49bae98a0746|c:\\PREPREPREwindowsPOSTPOSTPOST\\system32\\mswsock.dll"
  ], 
  "path": "c:\\documents and settings\\administrator\\local settings\\temp\\rad17929.tmp\\svchost.exe", 
  "regmod_count": 0, 
  "filemod_count": 0, 
  "segment": "", 
  "id": "7078511340675742078", 
  "unique_id": "623bec8f-8f8d-397e-0000-000000000001",
  "os_type": "windows"
}

```
-----
####  `/api/v1/binary`
Binary search.  Parameters passed as query string.

*Supports*:: `GET`

##### Parameters:
- `q`: REQUIRED Query string. Accepts the same data as the search box on the Binary Search page. See https://github.com/carbonblack/cbapi/blob/master/client_apis/docs/query_overview.pdf 
- `rows`: OPTIONAL Return this many rows, 10 by default.
- `start`: OPTIONAL Start at this row, 0 by default.
- `sort`: OPTIONAL Sort rows by this field and order.  `server_added_timestamp desc` by default.  
- `facets`: OPTIONAL Return facet results.  'false' by default, set to 'true' for facets.

##### Returns:
JSON object with the following elements:

- `results`: a list of matching binaries (see below for binary object)
- `terms`: a list of strings, each representing a token as parsed by the query parser
- `total_results`: number of matching binaries
- `start`: index of first row
- `elapsed`: clock time elapsed resolving this request  
- `highlights`: a list of highlight objects matching the query string.  Format the same as the process event object.
- `facets`: a list of facet entries if requested. (see below for facet object)

*Binary Object*

A binary object contains the following fields:

- `md5`: the md5 hash of this binary
- `server_added_timestamp`: the first time this binary was received on the server in the server GMT time
- `orig_mod_len`: Filesize in bytes
- `copied_mod_len`: Bytes copied from remote host, if file is > 25MB this will be less than `orig_mod_len`
- `observed_filename`: The set of unique filenames this binary has been seen as
- `is_executable_image:` 'true' or 'false' - 'true' if an EXE
- `is_64bit`: 'true' or 'false' - 'true' if x64 
- `product_version`: If present, Product version from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `product_name`: If present, Product name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `file_Version`: If present, File version from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `company_name`: If present, Company name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `internal_name`: If present, Internal name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `product_name`: If present, Product name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `legal_copyright`: If present, Legal copyright from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `legal_trademark`: If present, Legal trademark from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `file_desc`: If present, File description from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `original_filename`: If present, Original filename from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `private_build`: If present, Private build from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `special_build`: If present, Special build from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `signed`: Digital signature status: One of `Signed`, `Unsigned`, `Expired`, `Bad Signature`, `Invalid Signature`, `Invalid Chain`, `Untrusted Root`, `Explicit Distrust`
- `digsig_result`: Digital signature status: One of `Signed`, `Unsigned`, `Expired`, `Bad Signature`, `Invalid Signature`, `Invalid Chain`, `Untrusted Root`, `Explicit Distrust`
- `digsig_result_code`: HRESULT_FROM_WIN32 for the result of the digital signature operation via [WinVerifyTrust](http://msdn.microsoft.com/en-us/library/windows/desktop/aa388208)
- `digsig_sign_time`: If signed, the timestamp of the signature in GMT
- `digsig_publisher`: If signed and present, the publisher name
- `digsig_prog_name`: If signed and present, the program name
- `digsig_issuer`: If signed and present, the issuer name
- `digsig_subject`: If signed and present, the subject
- `alliance_score_virustotal`: If enabled and the hit count > 1, the number of [VirusTotal](http://virustotal.com) hits for this md5
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

 
*Facet object* 

The facet object is a list of dictionaries with the following keys.  Each key is a list of facet results objects that contain the top 200 name, value and percentage for the unique set of results matching the search.  

- `product_name_facet`: the top unique product names for the binaries matching the search
- `file_version_facet`: the top unique file versions for the binaries matching the search
- `alliance_score_virustotal`: the distribution of VirusTotal scores for binaries matching the search
- `digsig_result`: the distribution of signature status results for binaries matching the search
- `company_name_facet`: the top unique company names for the binaries matching the search
- `digsig_publisher_facet`: the top unique publisher names for the binaries matching the search
- `product_name_facet`: the top unique company anmes for the binaries matching the search
- `digsig_sign_time`: the distribution of signature times per month for the last 48 months for binaries matching the search
- `server_added_timestamp`: the distribution of server_added_timestamps per day for the last 30 days 
- `observed_filename_facet`: the top unique observed filenames for the binaries matching the search

The facet result objects have the same format as the process facet result objects above. 

A complete example:

```
GET http://192.168.206.151/api/binary?q=notepad.exe

{
  "total_results": 1, 
  "facets": {}, 
  "elapsed": 0.046832799911499023, 
  "start": 0,
  "results": [
    {
      "md5": "F2C7BB8ACC97F92E987A2D4087D021B1", 
      "digsig_result": "Signed", 
      "observed_filename": [
        "c:\\windows\\system32\\notepad.exe"
      ], 
      "product_version": "6.1.7600.16385", 
      "signed": "Signed", 
      "digsig_sign_time": "2009-07-14T10:17:00Z", 
      "orig_mod_len": 193536, 
      "is_executable_image": true, 
      "is_64bit": true, 
      "digsig_publisher": "Microsoft Corporation", 
      "file_version": "6.1.7600.16385 (win7_rtm.090713-1255)", 
      "company_name": "Microsoft Corporation", 
      "internal_name": "Notepad", 
      "product_name": "Microsoft\u00ae Windows\u00ae Operating System", 
      "digsig_result_code": "0", 
      "timestamp": "2013-08-16T11:26:48.321Z", 
      "copied_mod_len": 193536, 
      "server_added_timestamp": "2013-08-16T11:26:48.321Z", 
      "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.", 
      "original_filename": "NOTEPAD.EXE", 
      "file_desc": "Notepad",
      "os_type": "windows"
    }
  ],
  "terms": [
    "notepad.exe"
  ],
  "highlights": [
    {
      "name": "PREPREPRENOTEPAD.EXEPOSTPOSTPOST", 
      "ids": [
        "F2C7BB8ACC97F92E987A2D4087D021B1"
      ]
    }, 
    {
      "name": "c:\\windows\\system32\\PREPREPREnotepad.exePOSTPOSTPOST", 
      "ids": [
        "F2C7BB8ACC97F92E987A2D4087D021B1"
      ]
    }
  ], 
}
```
-----
####  `/api/v1/binary/(md5)`
Download the binary with this md5 hash.

*Supports*:: `GET`

##### Parameters:
- `md5`: REQUIRED the md5 hash of the binary

##### Returns:
A zipfile with the binary bytes and a text file with metadata. 

-----

####  `/api/v1/binary/(md5)/icon`
Returns the icon for the binary with the provided md5

*Supports*:: `GET`

##### Parameters:
- `md5`: REQUIRED the md5 of the binary  

##### Returns:
A PNG with the icon.  If the icon is not found, it returns the default Windows icon.

-----

####  `/api/v1/binary/(md5)/summary`
Returns the metadata for the binary with the provided md5

*Supports*: `GET`

##### Parameters:
- `md5`: REQUIRED the md5 of the binary  

##### Returns:
A structure with the following fields:

- `md5`: the md5 hash of this binary
- `server_added_timestamp`: the first time this binary was received on the server in the server GMT time
- `orig_mod_len`: Filesize in bytes
- `copied_mod_len`: Bytes copied from remote host, if file is > 25MB this will be less than `orig_mod_len`
- `observed_filename`: A list of strings, one per unique filename this binary has been seen as
- `is_executable_image:` 'true' or 'false' - 'true' if an EXE
- `is_64bit`: 'true' or 'false' - 'true' if x64 
- `product_version`: If present, Product version from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `product_name`: If present, Product name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `file_Version`: If present, File version from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `company_name`: If present, Company name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `internal_name`: If present, Internal name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `product_name`: If present, Product name from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `legal_copyright`: If present, Legal copyright from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `legal_trademark`: If present, Legal trademark from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `file_desc`: If present, File description from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `original_filename`: If present, Original filename from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `private_build`: If present, Private build from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `special_build`: If present, Special build from [FileVersionInformation](http://msdn.microsoft.com/en-us/library/system.diagnostics.fileversioninfo.aspx)
- `signed`: Digital signature status: One of `Signed`, `Unsigned`, `Expired`, `Bad Signature`, `Invalid Signature`, `Invalid Chain`, `Untrusted Root`, `Explicit Distrust`
- `digsig_result`: Digital signature status: One of `Signed`, `Unsigned`, `Expired`, `Bad Signature`, `Invalid Signature`, `Invalid Chain`, `Untrusted Root`, `Explicit Distrust`
- `digsig_result_code`: HRESULT_FROM_WIN32 for the result of the digital signature operation via [WinVerifyTrust](http://msdn.microsoft.com/en-us/library/windows/desktop/aa388208)
- `digsig_sign_time`: If signed, the timestamp of the signature in GMT
- `digsig_publisher`: If signed and present, the publisher name
- `digsig_prog_name`: If signed and present, the program name
- `digsig_issuer`: If signed and present, the issuer name
- `digsig_subject`: If signed and present, the subject
- `alliance_score_virustotal`: If enabled and the hit count >= 1, the number of [VirusTotal](http://virustotal.com) hits for this md5
- `alliance_score_srs`: If enabled and available, the Bit9 Software Reputation Service (SRS) score, normalized to a CB score
- `alliance_score_tis`: If enabled and available, the Bit9 Threat Indicators Service (TIS) score, normalized to a CB score
- `alliance_score_*`: 0 or more other scores, applied by configuring feeds.
- `endpoint`: list of 0 or more hostname,sensorid tuples on which this binary was observed.  The | character serves as the delimiter between the hostname and the sensorid.
- `group`: list of 0 or more sensor groups (by name) in which this binary was observed
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx


A complete example:

```
GET http://192.168.206.154/api/binary/1C8B787BAA52DEAD1A6FEC1502D652f0/summary

{
  "product_version_facet": "8.00.7600.16385", 
  "digsig_result": "Signed", 
  "observed_filename": [
    "c:\\windows\\system32\\mshtml.dll"
  ], 
  "product_version": "8.00.7600.16385", 
  "product_name_facet": "Windows\u00ae Internet Explorer", 
  "signed": "Signed", 
  "digsig_sign_time": "2010-11-21T03:36:00Z", 
  "orig_mod_len": 8988160, 
  "is_executable_image": false, 
  "is_64bit": true, 
  "observed_filename_facet": [
    "c:\\windows\\system32\\mshtml.dll"
  ], 
  "file_version_facet": "8.00.7600.16385 (win7_rtm.090713-1255)", 
  "digsig_publisher": "Microsoft Corporation", 
  "file_version": "8.00.7600.16385 (win7_rtm.090713-1255)", 
  "company_name": "Microsoft Corporation", 
  "internal_name": "MSHTML", 
  "_version_": 1446430562211332096, 
  "product_name": "Windows\u00ae Internet Explorer", 
  "digsig_result_code": "0", 
  "timestamp": "2013-09-17T13:14:37.636Z", 
  "company_name_facet": "Microsoft Corporation", 
  "copied_mod_len": 8988160, 
  "server_added_timestamp": "2013-09-17T13:14:37.636Z", 
  "md5": "1C8B787BAA52DEAD1A6FEC1502D652F0", 
  "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.", 
  "digsig_publisher_facet": "Microsoft Corporation", 
  "original_filename": "MSHTML.DLL.MUI", 
  "file_desc": "Microsoft (R) HTML Viewer",
  "os_type": "windows",
  "group": [
    "Default Group",
    "Domain Controllers"
  ],
  "endpoint": [
    "DC01|17",
    "XP-KIOSK-32|1002",
    "XP-KIOSK-87|688"
  ]
}
```

-----

#### `/api/v1/license`
License status and application

*Supports*: 'GET', 'POST'

##### Parameters:
 - Carbon Black-provided license (POST) 

##### Returns

- A GET returns the current license status, as defined below:

A license status dictionary has the following structure:

- `license_valid`: boolean indication as to if the licence is valid.  A valid license may be expired or unexpired.
- `license_end_date`: YYYY-MM-DD date on which the license expires
- `licensed_sensor_count`: number of sensors that can be used with this server while staying compliant with license.
- `server_token`: unique identifier for this particular server instance
- `license_expired`: boolean indicator as to if the license is expired
- `licensed_sensor_count_exceeded`: boolean indicator as to if the server is currently servicing more sensors than it is licensed for
- `actual_sensor_count`: count of sensors serviced during previous day (midnight to midnight)
- `license_request_block`: an opaque request block to be provided to Carbon Black for license renewal

-----

#### `/api/v1/settings/global/platformserver`
Get and set the configuration details of the Bit9 Platform Server.  These details are used for Carbon Black Enterprise Server integration with the Bit9 Platform Server.

*Supports*: 'GET', 'POST'

##### Parameters, Returns

- A GET returns a JSON dictionary as defined below.  A POST accepts a JSON dictionary with one or more keys as defined below.

- `server_url`: OPTIONAL the base server IP or DNS name.  The protocol and the URI are not included.
- `ssl_certificate_verify`: OPTIONAL indication as to if Carbon Black server should verify the Platform Server SSL certificate; valid values are 'true' and 'false'
- `watchlist_export`: OPTIONAL indication as to if the Carbon Black server should export, via HTTPS POST, watchlist hits to the Platfrom Server; valid values are 'true' and 'false'
- `auth_token`: OPTIONAL authorization token used by the Carbon Black server to authenticate against the Platform Server.

The `auth_token` field is never returned via HTTP GET for security purposes.

-----

#### `/api/v1/watchlist/(id)`
Watchlist enumeration, creation, modification, and deletion

*Supports*: 'GET', 'PUT', 'POST', 'DELETE'

##### Parameters:
- `id`: OPTIONAL the watchlist id

##### Notes

- Using the optional 'id' parameter, a caller may create a watchlist with a specific, known id.  This can be useful as the watchlist id is included as part of the underlying process or binary document and therefore can be used as as search criteria.

##### Returns

- With no id parameter (`GET /api/v1/watchlist`) returns a list of watchlists, with each list entry describing one watchlist
- With an id parameter (`GET /api/v1/watchlist/3`) returns the watchlist record for the matching id
- With no id parameter (`POST` /api/v1/watchlist) returns the watchlist record for the newly created watchlist
- With an id parameter (`PUT` /api/v1/watchlist/3) returns the watchlist record for the newly updated watchlist

A watchlist record has the following structure:

- `id`: the id of this watchlist
- `alliance_id`: the id of this watchlist on the Carbon Black Alliance server; this value is internal to Carbon Black
- `from_alliance`: boolean indication as to if this watchlist was provided by the Carbon Black Alliance Server
- `date_added`: the date this watchlist was created on this Enterprise Server
- `index_type`: the type of watchlist.  Valid values are 'modules' and 'events' for binary and process watchlists, respectively
- `last_hit`: timestamp of the last time this watchlist triggered a match
- `last_hit_count`: count of lifetime watchlist matches
- `name`: name of this watchlist
- `search_query`: the raw Carbon Black query that this watchlist matches 

A complete example:
```
GET http://192.168.206.154/api/v1/watchlist

{
 u'alliance_id': None,
 u'date_added': u'2013-12-11 11:36:38.476886-08:00',
 u'from_alliance': False,
 u'id': 4,
 u'index_type': u'modules',
 u'last_hit': u'2013-12-11 15:05:04.964374-08:00',
 u'last_hit_count': 22,
 u'name': u'Newly Loaded Modules',
 u'search_query': u'q=is_executable_image%3Afalse&cb.urlver=1&sort=server_added_timestamp%20desc'
 }
```

-----

#### `/api/v1/feed/(id)`
Feed enumeration, creation, modification, and deletion

*Supports*: 'GET', 'PUT', 'POST', 'DELETE'

##### Parameters:
- `id`: OPTIONAL the feed id

##### Returns

- With no id parameter (`GET /api/v1/feed`) returns a list of configured feeds, with each list entry describing one feed 
- With no id parameter (`POST` /api/v1/feed) returns the feed record for the newly created feed 
- With an id parameter (`PUT` /api/v1/feed/<id>) returns the feed record for the newly updated feed 

A feed record has the following structure:

- `provider_url`: URL associated with the feed as a whole; this is a human-consumable link to more information about the feed provider and is not consumed by the Carbon Black server
- `display_name`: Name of the feed as displayed in the Carbon Black web console
- `name`: internal name of the feed; must be alphanumeric.  used when searching e.g. alliance_score_feedname:[10 to *]
- `feed_url`: url of the feed itself; must begin with one of file:// http:// or https://
- `enabled`: boolean indicator as to if the feed is enabled
- `summary`: human-consumable summary of the feed
- `tech_data`: human-consumable technical summary of the feed
- `validate_server_cert`: boolean indicator as to if the Carbon Black server should verify the feed server certificate.  only applies to feeds provided via HTTPS
- `id`: internal id of the feed; this id is used during feed modification and deletion
- `icon`: base64-encoded icon representing the feed
- `manually_added`: boolean indicator as to if the feed was added manually.  If logical false, this means the feed was provided by the Carbon Black Alliance
- `order`: a numeric hint as to the display order in the Carbon Black web console
- `use_proxy`: boolean indicator as to if the Carbon Black server should use a web proxy when retrieving the feed contents

-----

####  `/api/v1/sensor/(id)?hostname=(hostname)&ip=(ipaddr)`
Sensor / remote client details

*Supports*: `GET` for all variations, `PUT` for `/api/v1/sensor/(id)` to update `event_log_flush_time`

##### Parameters:
- `id`: OPTIONAL the sensor id
- `hostname`: OPTIONAL returns the sensor record(s) with matching hostname
- `ipaddr`: OPTIONAL returns the sensor record(s) with specified IP address

##### Returns:

- With no parameters (`GET /api/v1/sensor`) returns a list of sensor structures, one per registered sensor.
- With a sensor id, (`GET /api/v1/sensor/12`) returns a sensor structure for the specified sensor.
- With a query string, (`GET /api/v1/sensor?hostname=foo`) returns a list of all sensors matching criteria

Sensor query strings are case-sensitive substring searches, for both `hostname` and `ip` fields.  If both 
`hostname` and `ip` fields are specified, only `ip` is used. 

A sensor structure has the following fields:

- `id`: this sensor's id
- `build_id`: the sensor version installed on this endpoint.  From the `/api/builds/` endpoint
- `build_version_string`: Human-readable string of the host's installed sensor version
- `uptime`: Host's uptime in seconds
- `systemvolume_total_size`: size in bytes of the computer's system volumn
- `systemvolume_free_size`: bytes free on the system volume
- `os_environment_display_string`: Human-readable string of the installed OS
- `os_environment_id`: the operating system installed on this computer.  From the internal table.
- `physical_memory_size`: size in bytes of physical memory
- `computer_dns_name`: this computer's DNS name
- `computer_name`: NetBIOS name of this computer
- `sensor_health_message`: Human-readable string indicating sensor's self-reported status
- `computer_sid`: Machine SID of this host
- `event_log_flush_time`: See below.
- `last_checkin_time`: Last communication with this computer in server-local time and zone
- `network_adapters`: A pipe-delimited list list of IP,MAC pairs for each network interface
- `sensor_health_status`: sensor's self-reported health score, from 0 to 100.  Higher numbers better
- `registration_time`: Time this sensor originally registered in server-local time and zone
- `next_checkin_time`: Next expected communication from this computer in server-local time and zone
- `boot_id`: A sequential counter of boots since the sensor was installed
- `group_id`: The sensor group id this sensor is assigned to
- `display`: Deprecated
- `uninstall`: when set, indicates sensor will be directed to uninstall on next checkin
- `parity_host_id`: Bit9 Platform Agent Host Id; zero indicates Agent is not installed
 
If `event_log_flush_time` is set, the server will instruct the sensor to immediately send all data before this date, 
ignoring all other throttling mechansims.  To force a host current, set this value to a value far in the future.
When the sensor has finished sending it's queued data, this value will be null. 

A complete example:
```
GET http://192.168.206.154/api/v1/sensor/1

{
  "systemvolume_total_size": "42939584512", 
  "os_environment_display_string": "Windows XP Professional Service Pack 3", 
  "sensor_uptime": "638", 
  "physical_memory_size": "536330240", 
  "build_id": 1, 
  "uptime": "666", 
  "computer_dns_name": "j-8205a0c27a0c4", 
  "id": 1, 
  "systemvolume_free_size": "40167079936", 
  "sensor_health_message": "Healthy", 
  "build_version_string": "003.002.000.30829", 
  "computer_sid": "S-1-5-21-1715567821-507921405-682003330", 
  "event_log_flush_time": null, 
  "computer_name": "J-8205A0C27A0C4", 
  "last_checkin_time": "2013-09-10 07:08:37.378860-07:00", 
  "license_expiration": "1990-01-01 00:00:00-08:00", 
  "network_adapters": "192.168.206.156,000c298a3613|", 
  "sensor_health_status": 100, 
  "registration_time": "2013-09-10 06:49:21.261157-07:00", 
  "next_checkin_time": "2013-09-10 07:09:07.368285-07:00", 
  "notes": null, 
  "os_environment_id": 1, 
  "boot_id": "5", 
  "cookie": 1291426991, 
  "group_id": 1, 
  "display": true, 
  "uninstall": false
}

http://192.168.206.132/api/v1/sensor?hostname=A0C4

[
  {
    "systemvolume_total_size": "42939584512", 
    "os_environment_display_string": "Windows XP Professional Service Pack 3", 
    "sensor_uptime": "480763", 
    "physical_memory_size": "536330240", 
    "build_id": 1, 
    "uptime": "480862", 
    "event_log_flush_time": null, 
    "computer_dns_name": "j-8205a0c27a0c4", 
    "id": 1, 
    "power_state": 0, 
    "uninstalled": null, 
    "systemvolume_free_size": "40083230720", 
    "status": "Online", 
    "num_eventlog_bytes": "22717", 
    "sensor_health_message": "Healthy", 
    "build_version_string": "004.000.000.30910", 
    "computer_sid": "S-1-5-21-1715567821-507921405-682003330", 
    "next_checkin_time": "2013-10-07 07:54:36.909657-07:00", 
    "node_id": 0, 
    "cookie": 556463980, 
    "computer_name": "J-8205A0C27A0C4", 
    "license_expiration": "1990-01-01 00:00:00-08:00", 
    "network_adapters": "192.168.206.156,000c298a3613|", 
    "sensor_health_status": 100, 
    "registration_time": "2013-02-04 06:40:04.632053-08:00", 
    "restart_queued": false, 
    "notes": null, 
    "num_storefiles_bytes": "446464", 
    "os_environment_id": 1, 
    "boot_id": "8", 
    "last_checkin_time": "2013-10-07 07:54:06.919446-07:00", 
    "group_id": 1, 
    "display": true, 
    "uninstall": false
  }
]
```

-----

####  `/api/v1/group/<groupid>/installer/windows/exe`
Download a zip archive including a signed Windows EXE sensor installer

*Supports*: `GET` 

##### Parameters:
None

##### Returns:

- ZIP archive including a signed Windows EXE sensor installer and settings file  

-----

####  `/api/v1/group/<groupid>/installer/windows/msi`
Download a zip archive including a signed Windows MSI sensor installer

*Supports*: `GET` 

##### Parameters:
None

##### Returns:

- ZIP archive including a signed Windows MSI sensor installer and settings file  

-----

####  `/api/v1/group/<groupid>/installer/osx`
Download a zip archive including a signed OSX PKG sensor installer

*Supports*: `GET`

##### Parameters:
None

##### Returns:

- ZIP archive including a signed OSX PKG sensor installer and settings file

##### Notes:

- Requires Carbon Black Enterprise Server 4.2.1 or greater

------

#### `/api/v1/group/<groupid>/installer/linux`
Download a zip archive including a Linux sensor installer

*Supports*: `GET`

##### Parameters:
None

##### Returns:

- compressed tarball (tar.gz) archive including a Linux sensor installer and settings file

##### Notes:

- Requires Carbon Black Enterprise Server 4.2.1 or greater

#### `/api/v1/sensor/statistics`
Get global sensor statistics

*Supports*: `GET`

##### Parameters:
None

##### Notes:

- Backlog counts are as of sensor checkin time.  Any bytes pushed post-checkin, in response to a server directive, are not accounted for.  This means total backlog appears artificially high and will never reach zero while sensors are active. 

##### Returns:

Returns a JSON dictionary with fields as follows:

sensor_count: total registered sensors
active_sensor_count: number of sensors active within the last 24 hours
num_eventlog_bytes: total backlog, in bytes, of eventlogs on active sensors.  See notes.
num_storefile_bytes: total backlog, in bytes, of binary files (store files) on active sensors.  See notes.
