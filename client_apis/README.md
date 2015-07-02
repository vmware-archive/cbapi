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
- [`/api/v1/sensor/<sensor_id>`](#apiv1sensorsensorid) -Sensor sync with event_log_flush_time
- [`/api/group`](#apigroup) - Sensor Group enumeration and addition
- [`/api/group/<group_id>`](#apigroup<group_id>) Specific sensor group information retrieval and deletion

#### Watchlists
- [`/api/v1/watchlist`](#apiv1watchlist) - Watchlist enumeration, addition, modification, and deletion

#### Feeds
- [`/api/v1/feed`](#apiv1feed) - Feed enumeration and addition
- [`/api/v1/feed/<id>`](#apiv1feedid) - Feed modification and deletion
- [`/api/v1/feed/id/action`](#apiv1feedidaction) - Feed action enumeration and addition
- [`/api/v1/feed/id/action/<action_id>`](#apiv1feedactionactionid) - Feed action updating and deletion

#### Users
- [`/api/users`](#apiusers) - User enumeration
- [`/api/user`](#apiuser) - User addition
- [`/api/user/<username>`](#apiuser<username>) - Specific user information retrieval and user deletion
- [`/api/useractivity`](#apiuseractivity) - Retrieve all, failed, or successful attempts from a user to connect to the server

#### Teams
- [`/api/teams`](#apiteams) - Team enumeration
- [`/api/team`](#apiteam) - Team addition
- [`/api/team/<team_id>`](#apiteam<team_id>) - Team information retrieval, and deletion

#### Alerts
- [`/api/v1/alert`](#apiv1alert) - Alert search
- [`/api/v1/alert/<alertid>`](#apiv1alertalertid) - Alert update and resolution

#### Banning 
- [`/api/v1/banning/blacklist`] (#apiv1banningblacklist) - Banned md5 hash enumeration and addition
- [`/api/v1/banning/blacklist/<md5>`] (#apiv1banningblacklistmd5) - Specific banned md5 hash retrieval,update, and disabling
- [`/api/v1/banning/whitelist`] (#apiv1banningwhitelist) - Retrieval of the banned md5 hash whitelist
- [`/api/v1/banning/restrictions`] (#apiv1banningrestrictions) - Retrieval of the banned md5 hash restrictions

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
- `facet`: OPTIONAL Return facet results.  'false' by default, set to 'true' for facets.

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
- `crossproc_count`: the count of cross process events launched by this process
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
GET http://192.168.206.151/api/v1/process?q=notepad.exe

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
- `crossproc_complete`: a pipe-delimited list of crossproc string
- `os_type`: operating system type of the computer for this process; one of windows, linux, osx

Each xxx_complete record is a string similar to:

```
2013-09-19 22:07:07.000000|f404e59db6a0f122ab26bf4f3e2fd0fa|c:\\windows\\system32\\dxgi.dll"
```

The pipe character (`|`) delimits the fields.  

##### filemod_complete
```
"1|2013-09-16 07:11:58.000000|c:\\documents and settings\\administrator\\local settings\\temp\\hsperfdata_administrator\\3704|||false"
```
- field 0: operation type, an integer 1, 2, 4 or 8
  - 1: Created the file
  - 2: First wrote to the file
  - 4: Deleted the file
  - 8: Last wrote to the file
- field 1: event time
- field 2: file path
- field 3: if operation type (field 0) is 8, last write, this value is the md5 of the file after the last write
- field 4: file type, if known, an integer
  - 1: PE
  - 2: Elf
  - 3: UniversalBin
  - 8: EICAR
  - 16: OfficeLegacy
  - 17: OfficeOpenXml
  - 48: Pdf
  - 64: ArchivePkzip
  - 65: ArchiveLzh
  - 66: ArchiveLzw
  - 67: ArchiveRar
  - 68: ArchiveTar
  - 69: Archive7zip
- field 5: boolean "true" if event is flagged as potential tamper attempt; "false" otherwise

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

##### childproc_complete
```
"2014-01-23 09:19:08.331|8832db0c-6b84-fc4b-0000-000000000001|51138beea3e2c21ec44d0932c71762a8|c:\windows\system32\rundll32.exe|6980|true|false"
```
- field 0: event time
- field 1: unique_id of the child process
- field 2: md5 of the child process
- field 3: path of the child process
- field 4: PID of child process
- field 5: boolean "true" if child process started; "false" if terminated
- field 6: boolean "true" if event is flagged as potential tamper attempt; "false" otherwise
 
##### crossproc_complete
```
"ProcessOpen|2014-01-23 09:19:08.331|00000177-0000-0258-01cf-c209d9f1c431|204f3f58212b3e422c90bd9691a2df28|c:\windows\system32\lsass.exe|1|2097151|false"
```
- field 0: type of cross-process access: RemoteThread if remote thread creation; ProcessOpen if process handle open with access privileges
- field 1: event time
- field 2: unique_id of the targeted process
- field 3: md5 of the targeted process
- field 4: path of the targeted process
- field 5: sub-type for ProcessOpen, "1" for handle open to process; "2" for handle open to thread in process
- field 6: requested access priviledges
- field 7: boolean "true" if event is flagged as potential tamper attempt; "false" otherwise


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
- `crossproc_complete`: a pipe-delimited list of **summary** crossproc string (see spec above)
- `modload_count`: the **total** count of modules loaded in this process
- `regmod_count`: the **total** count of registry modifications in this process
- `filemod_count`: the **total** count of file modifications in this process
- `netconn_count`: **total** count of network connections in this process
- `childproc_count`: the **total** count of child processes launched by this process
- `crossproc_count`: the **total** count of cross process events launched by this process
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
- `facet`: OPTIONAL Return facet results.  'false' by default, set to 'true' for facets.

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

#### `/api/v1/alert`

Alert search

*Supports*: 'GET', 'POST'

##### Parameters:
- `q`: REQUIRED Query string. Accepts the same data as the alert search box on the Triage Alerts page. 
- `rows`: OPTIONAL Return this many rows, 10 by default.
- `start`: OPTIONAL Start at this row, 0 by default.
- `sort`: OPTIONAL Sort rows by this field and order.  `last_update desc` by default.
- `facets`: OPTIONAL Return facet results.  'false' by default, set to 'true' for facets.

##### Returns:

 - JSON dictionary describing the alert search results

#### `/api/v1/alert/(alertid)`

Alert update and resolution

*Supports*: 'POST'

##### Parameters:
- `unique_id`: REQUIRED Unique ID of alert to update
- `status`: REQUIRED Status of the alert, as a string

##### Returns:

 - JSON dictionary describing alert

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

####/api/v1/feed/id/action/(action_id)
*Supports* `GET` and `POST` for `/api/v1/feed/id/action`  
*Supports* `PUT` and `DELETE` for `/api/v1/feed/id/action/<action_id>`

#####Returns

- With no "action_id" parameter, `GET /api/v1/feed/id/action` returns a JSON object with a list of all the actions enabled for this feed
- With no "action_id" parameter, `POST /api/v1/feed/id/action` returns whether or not the posting effort was successful.
- With an "action_id" parameter, `PUT /api/v1/feed/id/action/action_id` returns whether or not the updating effort was successful.
- With an "action_id" parameter, `DELETE /api/v1/feed/id/action/action_id` returns whether or not the action was able to be deleted.

a JSON object with a list of all the feed actions has the following structure:
+ a list of actions, each with the following structure:
    + `action_data`: the action data including a list of email recipients
    + `action_type`: the type of action, 0 for email, 1 for write to syslog, 3 for create alert 
    + `group_id`: the id of the feed this action is enabled for
    + `watchlist_id`: id of watchlist that employs this feed

Example:
```
GET /api/v1/feed/6/action
[
    {
        action_data: "{"email_recipients":[2]}"
        action_type: 3
        group_id: 6
        id: 18
        watchlist_id: null
    },
    {
        action_data: "{"email_recipients":[2]}", 
        action_type: 1
        group_id: 6
        id: 22
        watchlist_id: null
    }
]
```

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
- `network_isolation_enabled`: Boolean representing network isolation request status.  See below for details.
- `is_isolating`: Boolean representing sensor-reported isolation status.  See below for details.
 
If `event_log_flush_time` is set, the server will instruct the sensor to immediately send all data before this date, 
ignoring all other throttling mechansims.  To force a host current, set this value to a value far in the future.
When the sensor has finished sending it's queued data, this value will be null. 

Network isolation is requested by setting `network_isolation_enabled` to `true`.   When the sensor receives the request and enables isolation, `is_isolating` will be set to `true`.   The combination of the two parameters creates the following potential states:

| Phase | `network_isolation_enabled` | `is_isolating` | State | 
| ----- | --------------------------- | -------------- | ----- | 
| 0     |  False | False | normal state, isolation neither requested nor active | 
| 1     |  True  | False | Isolation requested but not yet active | 
| 2     | True   | True  | Isolation requested and active | 
| 3     | False  | True  | Isolation disabled, but still active | 

Transitions between states 0 to 1 and states 2 to 3 will be delayed by a few minutes, based on sensor checkin interval and online status.

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
  "uninstall": false,
  "network_isolation_enabled": false,
  "is_isolating": false
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
    "uninstall": false,
    "network_isolation_enabled": false,
    "is_isolating": false
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


#### `/api/user/(username)` and `/api/users`
User enumeration, addition, modification, and deletion.

*Supports*: `GET`, `POST`, `PUT`, `DELETE`

##### Parameters:

`username`: OPTIONAL the username of the user to retrieve, modify or delete.

##### Returns:

+ With no username parameter, GET `/api/users` returns a list of the current users.  
+ With a username parameter, GET `/api/user/<username>` returns a JSON object with the structure of a user.  
+ With a username parameter, DELETE `/api/user/<username>` returns a JSON object with the structure of the user   that was deleted.
+ With a username parameter, PUT `/api/user/<username> returns a JSON object with the structure of the updated user.  
+ With no username parameter, POST `/api/user` returns a JSON object with the structure of the added user.  

A user has the following structure:

+ `username`: username of the user.  
+ `first_name`: First name of the user.  
+ `last_name`: Last name of the user.  
+ `global_admin`: Whether or not the user is a global administrator (True or False).  
+ `auth_token`: Authorization token of the user.
+ `teams`: List of teams that the user is a member of.  
+ `email`: email address of the user.  

Example: 

```
GET https://172.16.100.109/api/user/jsmith

{
  "username": "jsmith",
  "first_name": "John",
  "last_name": "Smith",
  "global_admin": false,
  "auth_token": "dcbd1587c0c38f9e68d96572a41dbfca1c6f9f05",
  "teams": [
    {
      "id": 1,
      "name": "Administrators"
    },
    {
      "id": 2,
      "name": "Test"
    }
  ],
  "email": "jsmith@Bit9.com"
}
```

#### `/api/useractivity`
Enumeration of attempts from users to connect to server.

*Supports*: `GET` for `/api/useractivity`

#####Parameters:

None

#####Returns:

a list of the failed and successful attempts to access the server.


#### `/api/team/(id)` and `/api/teams`
Team enumeration, addition, modification, and deletion.

*Supports*: `GET`, `PUT`, `DELETE` for `/api/team/<id>`  
*Supports*: `POST` for `/api/team  
*Supports*: `GET` for /api/teams

#####Parameters:

`id`: OPTIONAL the id of the team to retrieve, modify or delete.

##### Returns: 

+ With an id parameter, `GET /api/team/<id>` returns a JSON object with the structure of the team to retrieve.
+ With an id parameter, `PUT /api/team/<id>` returns a JSON object with the structure of the updated team.
+ With an id parameter, `DELETE /api/team/<id>` returns a JSON object with the structure of the deleted team.
+ With no id parameter, `POST /api/team` returns a JSON object with the structure of the added team.
+ With no id parameter, `GET /api/teams` returns a JSON object with a list of the current teams.

A team has the following structure:

+ `id`: the id of the team.
+ `group_access`: a list of sensor groups the team has access to.
+ `name`: the name of the group.

Example: 

```
GET https://172.16.100.109/api/team/1
 
{
  "id": 1,
  "group_access": [
    {
      "group_id": 1,
      "access_category": "No Access",
      "group_name": "Default Group"
    },
    {
      "group_id": 9,
      "access_category": "No Access",
      "group_name": "AnotherGroup"
    },
    {
      "group_id": 8,
      "access_category": "No Access",
      "group_name": "TestGroupl"
    },
    {
      "group_id": 10,
      "access_category": "No Access",
      "group_name": "BarryGroup"
    }
  ],
  "name": "Administrators"
}
```
#### /api/group/(id)
Sensor group enumeration, modification, addition, and deletion.

*Supports*: `GET`, `PUT`, `DELETE` for `/api/group/<id>`
*Supports*: `GET`, `POST` for `/api/group`

#####Parameters:

`id`: OPTIONAL the id of the sensor group

#####Returns:

+ With an id parameter, `GET /api/group/<id>` returns a list of length one with the one element being the JSON object with the structure of the retrieved sensor group.
+ With an id parameter, `PUT /api/group/<id>` returns a JSON object with the structure of the modified sensor group.
+ With an id parameter, `DELETE /api/group/<id>` returns a JSON object with the structure of the deleted sensor group.
+ With no id parameter, `GET /api/group` returns a list of the current sensor groups.
+ With no id parameter, `POST /api/group` returns a JSON object with the structure of the added sensor group.

A sensor group has the following structure:

+ `alert_criticality`: a number 1-5 expressing the criticality of the alert.
+ `banning_enabled`: true/false enable banning.
+ `collect_cross_procs`: true/false collect cross process events.
+ `collect_emet_events`: true/false collect EMET events.
+ `collect_filemods`: true/false collect file modifications.
+ `collect_filewritemd5s`: true/false collect writing of md5 files.
+ `collect_moduleinfo`: true/false collect module info.
+ `collect_moduleloads`: true/false collect binary module(.dll, .sys, .exe) loads.
+ `collect_netconns`: true/false collect network connections.
+ `collect_nonbinary_filewrites`: true/false collect non-binary file writes.
+ `collect_processes`: true/false collect process information.
+ `collect_regmods`: true/false collect registry modifications.
+ `collect_storefiles`: true/false collect binary files.
+ `collect_usercontext`: true/false process user context.
+ `datastore_server`: the datastore server
+ `id`: the id of the sensor group
+ `max_licenses`: max number of licenses
+ `name`: name of the sensor group
+ `quota_eventlog_bytes`: limit in disk storage for eventlog
+ `quota_eventlog_percent`: percent of disk storage for eventlog
+ `quota_storefile_bytes`: limit in disk storage for storefiles 
+ `quota_storefile_percent`: percent of disk storage for storefiles
+ `sensor_exe_name`: sensor name
+ `sensor_version`: sensor upgrade policy
+ `sensorbackend_server`: server URL
+ `site_id`: the site id
+ `tamper_level`: tamper level settings (0 or 1 off or on)
+ `team_access` : a list of teams with access to this sensor group.
+ `vdi_enabled` : true/false enable VDI behavior

Example:

```
GET: https://172.16.100.109/api/group/1

[{
    alert_criticality: 3
    banning_enabled: true
    collect_cross_procs: true
    collect_emet_events: true
    collect_filemods: true
    collect_filewritemd5s: true
    collect_moduleinfo: true
    collect_moduleloads: true
    collect_netconns: true
    collect_nonbinary_filewrites: true
    collect_processes: true
    collect_regmods: true
    collect_storefiles: true
    collect_usercontext: true
    datastore_server: null 
    id: 1
    max_licenses: -1
    name: "Default Group"
    quota_eventlog_bytes: "1073741824"
    quota_eventlog_percent: 1
    quota_storefile_bytes: "1073741824"
    quota_storefile_percent: 1
    sensor_exe_name: ""
    sensor_version: "005.001.000.50513"
    sensorbackend_server: "https://172.16.100.109:443"
    site_id: 1
    tamper_level: 0
    team_access: [
            {
                team_id: 1, 
                team_name: "Administrators", 
                access_category: "No Access"
            },
            {
                team_id: 2, 
                team_name: "Test", 
                access_category: "No Access"
            },

            {
                team_id: 9, 
                team_name: "Temporary Team", 
                access_category: "Administrator"
            },
            {
                team_id: 10, 
                team_name: "Team1", 
                access_category: "No Access"
            },
            {
                team_id: 16, 
                team_name: "BarryTeam", 
                access_category: "Administrator"
            }
    ]
    vdi_enabled: false
}]
```

#### /api/v1/banning/blacklist/(md5)
Banned hash enumeration, modification, addition, retrieval, and disabling.

#####Returns:

+ With no md5 parameter, `GET /api/v1/banning/blacklist` returns a list of the currently banned hashes and their attributes, enabled or disabled.
+ With no md5 parameter, `POST /api/v1/banning/blacklist` returns a JSON object with the structure of the newly added banned hash
+ With an md5 parameter, `GET /api/v1/banning/blacklist/md5` returns a JSON object with the structure of the retrieved banned hash
+ With an md5 parameter, `PUT /api/v1/banning/blacklist/md5` returns a JSON object with the structure of the newly updated banned hash
+ With an md5 parameter, `DELETE /api/v1/banning/blacklist/md5` returns a JSON object with the structure of the disabled hash.

A banned hash has the following structure:

+ `username`: the username of the current user
+ `audit` : modifications to the banned hash
+ `block_count` : number of times this hash has been blocked
+ `user_id` : id of the current user
+ `timestamp` : time of access
+ `text` : The Notes section of the banned hash
+ `md5hash` : md5 hash of the file
+ `enabled` : Whether or not the CB server is scanning for this hash
+ `last_block_time` : the last time this hash was blocked
+ `last_block_hostname` : which sensor it was blocked on

Example:
```
GET https://172.16.100.109/api/v1/banning/blacklist/506708142bc63daba64f2d3ad1dcd5bf

    username : testuser
    audit:
       [0:{
            enabled: false
            text: "Testing"
            timestamp: "2015-06-03 16:53:24.755974-04:00"
            user_id: 25
            username: "bwolfson"
         }
        1:{username: "testuser", timestamp: "2015-06-03 16:50:30.740464-04:00", text: null, enabled: true,…}
        2: {username: "testuser", timestamp: "2015-06-03 16:43:51.345906-04:00", text: "updated enabled to False",…}
        3: {username: "testuser", timestamp: "2015-06-03 16:33:02.317667-04:00", text: "updated enabled to False",…}
        4: {username: "testuser", timestamp: "2015-06-03 16:32:59.524166-04:00", text: null, enabled: false,…}
        5: {username: "testuser", timestamp: "2015-06-03 12:50:19.381888-04:00", text: "updated enabled to False",…}
        6: {username: "admin", timestamp: "2015-05-20 02:23:34.638245-04:00", text: null, enabled: false,…}
        7: {username: "admin", timestamp: "2015-05-20 01:50:50.276626-04:00", text: null, enabled: true,…}
        8: {username: "admin", timestamp: "2015-05-20 01:50:39.626684-04:00", text: null, enabled: false,…}
        9: {username: "admin", timestamp: "2015-05-20 01:49:01.719130-04:00", text: "", enabled: true, user_id: 1}
       ]
    block_count: 6
    enabled: false  
    last_block_hostname: "TORTISE"
    last_block_sensor_id: 6
    last_block_time: "2015-06-03 16:13:49.788000-04:00"
    md5hash: "506708142bc63daba64f2d3ad1dcd5bf"
    text: "Testing"
    timestamp: "2015-06-03 16:53:24.755974-04:00"
    user_id: 25
    username: "testuser"
```

#### /api/v1/banning/whitelist 
Whitelist enumeration

*Supports*: `GET` for `/api/v1/banning/whitelist`

#####Returns:

`GET /api/v1/banning/whitelist` returns a JSON object with the structure of the retrieved whitelist

A whitelist JSON object has the following structure:

+ `whitelist`: The list of current executables in the whitelist

Example:
```
GET /api/v1/banning/whitelist

    whitelist: 
        [
            0: "%SystemRoot%\system32\svchost.exe"
            1: "%SystemRoot%\carbonblack\cb.exe"
            2: "%SystemRoot%\system32\smss.exe"
            3: "%SystemRoot%\system32\services.exe"
            4: "%SystemRoot%\system32\csrss.exe"
            5: "%SystemRoot%\system32\wininit.exe"
            6: "%SystemRoot%\system32\winlogon.exe"
            7: "%SystemRoot%\system32\lsass.exe"
        ]
```

####/api/v1/banning/restrictions
Restrictions enumeration

*Supports*: `GET` for `/api/v1/banning/restrictions`

#####Returns:

`GET /api/v1/banning/restrictions` returns a JSON object with the structure of the retrieved restrictions

A restrictions JSON object has the following structure:

+ `patterns` : The list of executables in restrictions

Example:
```
GET /api/v1/banning/restrictions

    patterns: 
        [
            0: "%SystemRoot%\system32\svchost.exe"
            1: "%SystemRoot%\carbonblack\cb.exe"
            2: "%SystemRoot%\system32\smss.exe"
            3: "%SystemRoot%\system32\services.exe"
            4: "%SystemRoot%\system32\csrss.exe"
            5: "%SystemRoot%\system32\wininit.exe"
            6: "%SystemRoot%\system32\winlogon.exe"
            7: "%SystemRoot%\system32\lsass.exe"
        ]
```

####/api/v1/dashboard/alliance
Dashboard alliance info

*Supports*: `GET` for `/api/v1/dashboard/alliance`

#####Returns:

`GET /api/v1/dashboard/alliance` returns a JSON object with the structure of the retrieved alliance 

An alliance JSON object has the following structure:

+ `alliance_client` : The alliance object which contains:  
    + `is_enabled` : whether or not the alliance client is enabled  
    + `last_failure_code` : the code for the last time the alliance client failed  
    + `is_connected` : whether or not the alliance client is connected  
    + `last_failure_time` : the time of the last failure

Example:
```
GET external.cloud.carbonblack.com/api/v1/dashboard/alliance

    alliance_client: 
        is_connected: false
        is_enabled: true
        last_failure_code: 600
        last_failure_time: "2015-06-08 20:42:17.721631+00:00"

```

####/api/v1/dashboard/hosts
Dashboard hosts info

*Supports*: `GET` for `/api/v1/dashboard/hosts`

#####Returns:

`GET /api/v1/dashboard/hosts` returns a JSON object with the structure of the retrieved hosts

A hosts JSON object has the following structure:

+ `hosts` : an array of host objects, each with the following fields:
    + `count`: 
    + `punctual`:
    + `group_id`:

Example:
```
GET external.cloud.carbonblack.com/api/v1/dashboard/hosts

    hosts:[  
        {
            count: 135, 
            punctual: false, 
            group_id: 1
        },
        {
            count: 1,
            punctual: false, 
            group_id: 2
        }]
```

####/api/v1/dashboard/statistics
Dashboard statistics info

*Supports*: `GET` for `/api/v1/dashboard/statistics`

#####Returns:

`GET /api/v1/dashboard/statistics` returns a JSON object with the structure of the dashboard statistics

A statistics JSON object has the following structure:

+ `storage` : a list of servers which the UI has data on, for example:
    + `192.237.206.117`: Server with a list of different statistic types such as:
        + `EventStoreStats`: a list of Event Store Stats with the following structure:
            + `CoreIndexSize`:
            + `FileSystemName`:
            + `MaxNumberDocuments`:
            + `NumberDocuments`:
            + `NumberSements`:
            + `ShardId`:
        + `FileSystems`: a list of file systems with the following structure:
            + `AvailableSize`:
            + `MountPoint`:
            + `Name`:
            + `TotalSize`:
            + `Type`:
            + `UsedSize`:
        + `ModuleInfoStoreStats`:
            + `CoreIndexSize`:
            + `FileSystemName`:
            + `MaxNumberDocuments`:
            + `NumberDocuments`:
            + `NumberSements`:
            + `ShardId`:
        + `ModuleStoreStats`:
            + `FileSystemName`:
            + `ModuleOnDiskCount`:
            + `RecordedModulesCount`:
            + `TotalSizeOnDisk`:
            + `TotalUncompressedSize`:
        + `SqlStoreStats`:
            + `FileSystemName`:
            + `Tables`: list of tables, each with structure as follows:
                + `TotalSize`:
                + `Name`:
                + `IndexSize`:
            + `TotalSize`:

####/api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/(count)/(sort) and
####/api/v1/detect/report/<feed_name>/unresolvedalertsbytime/(count)/(sort)
Enumeration of unresolved alerts by severity score or by time. 

*Supports* `GET` for `/api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/(count)/(sort)
*Supports* `GET` for `/api/v1/detect/report/<feed_name>/unresolvedalertsbytime/(count)/(sort)

#####Returns:

+ With no `count` and `sort` parameters, `GET /api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity`  
returns a JSON object with the first 10 unresolved alerts by severity in descending order  
  
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/count` returns a JSON object with the   "count" number of unresolved alerts by severity in descending order.
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity`  
returns a JSON object with the "count" number of unresolved alerts by severity in order specified by   "sort" (either ascending or descending)  

+ With no `count` or `sort` parameters, `GET /api/v1/detect/report/<feed_name>/unresolvedalertsbytime`  
returns a JSON object with the first 10 unresolved alerts by time in descending order
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/<feed_name>/unresolvedalertsbytime/count` returns a JSON object with the   "count" number of unresolved alerts by severity in descending order.  
  
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/<feed_name>/unresolvedalertsbytime`  
returns a JSON object with the "count" number of unresolved alerts by time in order specified by   "sort" (either ascending or descending)


A JSON object of unresolved alerts has the following structure:

a list of alerts, each with structure as follows:

+ `alert_severity` : severity score of the alert
+ `created_time` : Time of creation
+ `feed_name` : Name of the feed
+ `feed_rating` : rating of the feed
+ `ioc_confidence` : Indicator of Compromise confidence score
+ `md5` : md5 hash
+ `os_type` : Operating Systems type
+ `report_score` : Score for the report
+ `sensor_criticality` : criticality score of the sensor
+ `unique_id` : id of the unresolved alert

Example:
```
GET external.carbonblack.com/api/v1/detect/report/VirusTotal/unresolvedalertsbytime/3/asc

    [
        {
            alert_severity: 31.05
            created_time: "2014-12-26T23:12:23.369Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "96B43A7BDDEEE7DF98983B886DE56DC7"
            os_type: "windows"
            report_score: 46
            sensor_criticality: 3
            unique_id: "99140c84-55b9-4eee-aa46-658baeeacb93"
        },
        {
            alert_severity: 37.125
            created_time: "2014-12-27T00:33:06.449Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "A487BAE084BBD75ECBDC5D9FEDE362BA"
            os_type: "windows"
            report_score: 55
            sensor_criticality: 3
            unique_id: "32097e17-46c0-4ca5-bdf0-85b608edd908"
        },
        {    
            alert_severity: 44.55
            created_time: "2014-12-27T00:42:06.909Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "E23DBA4B28EB7543D6D6ED5E06EEBCB6"
            os_type: "windows"
            report_score: 66
            sensor_criticality: 3
            unique_id: "a4356d81-457b-4825-8537-d662e3d04b4f"
        }
    ]
```

####/api/v1/detect/report/<feed_name>/unresolvedalerttrend/(days)
Enumerates unresolved alerts over the last "days" number of days.

*Supports* `GET` for `/api/v1/detect/report/<feed_name>/unresolvedalerttrend/(days)`

#####Returns:

+ With no "days" parameter, `GET /api/v1/detect/report/<feed_name>/unresolvedalerttrend` returns a JSON object with the last 30 days worth of unresolved alerts.  

+ With a "days" parameter, `GET /api/v1/detect/report/<feed_name>/unresolvedalerttrend/days` returns a JSON object with the last "days" days worth of unresolved alerts.  

A JSON object with past days of unresolved alerts has the following structure:

+ `counts`: a list of the unresolved alerts over the last "days" number of days. Each has the following structure:    
    + `name`: Name of the alert
    + `value`: Value of the alert
+ `start`: The start time of the trend
+ `end`: The end time of the trend

Example:
```
GET `api/v1/detect/report/VirusTotal/unresolvedalerttrend

counts: [
          0:{
                name: "2015-05-11T00:00:00Z", 
                value: 453
            },
          1:{
                name: "2015-05-12T00:00:00Z",
                value: 450
            },
          2: {name: "2015-05-13T00:00:00Z", value: 452}
          3: {name: "2015-05-14T00:00:00Z", value: 451}
          4: {name: "2015-05-15T00:00:00Z", value: 444}
          5: {name: "2015-05-16T00:00:00Z", value: 443}
          6: {name: "2015-05-17T00:00:00Z", value: 441}
          7: {name: "2015-05-18T00:00:00Z", value: 451}
          8: {name: "2015-05-19T00:00:00Z", value: 447}
          9: {name: "2015-05-20T00:00:00Z", value: 445}
          10: {name: "2015-05-21T00:00:00Z", value: 444}
          11: {name: "2015-05-22T00:00:00Z", value: 449}
          12: {name: "2015-05-23T00:00:00Z", value: 444}
          13: {name: "2015-05-24T00:00:00Z", value: 448}
          14: {name: "2015-05-25T00:00:00Z", value: 447}
          15: {name: "2015-05-26T00:00:00Z", value: 450}
          16: {name: "2015-05-27T00:00:00Z", value: 453}
          17: {name: "2015-05-28T00:00:00Z", value: 449}
          18: {name: "2015-05-29T00:00:00Z", value: 449}
          19: {name: "2015-05-30T00:00:00Z", value: 448}
          20: {name: "2015-05-31T00:00:00Z", value: 443}
          21: {name: "2015-06-01T00:00:00Z", value: 451}
          22: {name: "2015-06-02T00:00:00Z", value: 452}
          23: {name: "2015-06-03T00:00:00Z", value: 453}
          24: {name: "2015-06-04T00:00:00Z", value: 448}
          25: {name: "2015-06-05T00:00:00Z", value: 451}
          26: {name: "2015-06-06T00:00:00Z", value: 463}
          27: {name: "2015-06-07T00:00:00Z", value: 443}
          28: {name: "2015-06-08T00:00:00Z", value: 452}
          29: {name: "2015-06-09T00:00:00Z", value: 452}
          30: {name: "2015-06-10T00:00:00Z", value: 445}
        ]
end: "2015-06-11T00:00:00Z"
start: "2015-05-11T00:00:00Z"
```

####/api/v1/detect/report/adminsbyalertsresolved/(count)/(sort) and 
####/api/v1/detect/report/adminsbyresolvedtime/(count)/(sort) 
Enumerates admin in order of number of alerts they have resolved or time spent resolving alerts

*Supports*: `GET` for `api/v1/detect/report/adminsbyalertsresolved/(count)/(sort)`  
*Supports*: `GET` for `api/v1/detect/report/adminsbyresolvedtime/(count)/(sort)`

#####Returns:
+ With no count parameter, `GET /api/v1/detect/report/adminsbyalertsresolved` returns a JSON object with maximum 10 enumerated admin sorted in descending order of how many alerts they have resolved.
  
+ With a count parameter and no sort parameter, `GET /api/v1/detect/report/adminsbyalertsresolved/count` returns a JSON object with the "count" number of admin sorted in descending order of how many alerts they have resolved.  
+ With both a count and sort parameters, `GET /api/v1/detect/report/adminsbyalertsresolve/count/sort returns a JSON object with the "count" number of admin sorted in "sort" order (Either 'asc' for ascending or 'desc' for descending)  

+ With no count parameter, `GET /api/v1/detect/report/adminsbyresolvedtime` returns a JSON object with maximum 10 enumerated admin sorted in descending order of resolved time.  
+ With a count parameter and no sort parameter, `GET /api/v1/detect/report/adminsbyresolvedtime/count` returns a JSON object with the "count" number of admin sorted in descending order of resolved time.
  
+ With both a count and sort parameters, `GET /api/v1/detect/report/adminsbyresolvedtime/count/sort returns a JSON object with the "count" number of admin sorted in "sort" order (Either 'asc' for ascending or 'desc' for descending

A JSON object of admin users organized by alerts resolved has the following structure:

+ a list of admin, each with the following structure:
    + `count`: Number of resolved alerts
    + `name`: Name of admin
    + `ratio`: Ratio of alerts resolved

A JSON object of admin users organized by time resolving has the following structure:

+ a list of admin, each with the following structure:
    + `average_hours`: Average hours spent resolving alerts
    + `name`: Name of admin
    + `ratio`: Ratio of time spent on resolving alerts

####/api/v1/detect/report/alertresolutionaverage/(days)
Enumerates resolution times over the last "days" number of days

*Supports*: `GET` for `/api/v1/detect/report/alertresolutionaverage(days)

#####Returns:
+ With no "days" parameter, `GET /api/v1/detect/report/alertresolutionaverage` returns a JSON object with the resolution data for each of the last 30 days.
+ With a "days" parameter, `GET /api/v1/detect/report/alertresolutionaverage/days` returns a JSON object with the resolution data for each of the last "days" number of days

A JSON object with the resolution data has the following structure:
+ `resolution_time`: a list of the resolution data, each of which has the following structure:
    + `date_offset`: Days away from present
    + `total_resolutions`: Total resolutions for that day
    + `average_in_seconds`: 
    + `time_stamp`: Time stamp

####/api/v1/detect/report/binarydwell/(days)
Enumerates the binary dwell over the last "days" number of days

*Supports*: `GET` for `/api/v1/detect/report/binarydwell/(days) 

#####Returns:
+ With no "days" parameter, `GET /api/v1/detect/report/binarydwell` returns a JSON object with binary dwell info over the last 250 days.
+ With a "days" parameter, `GET /api/v1/detect/report/binarydwell` returns a JSON object with binary dwell info over the last "days" number of days.

A JSON object with binary dwell info has the following structure:
+ `dwell`: a list of daily binary dwell info, each with the following structure:
    + `30_day_avg`: average over 30 days
    + `60_day_avg`: average over 60 days
    + `90_day_avg`: average over 90 days
    + `date_offset`: number of days away from present day
    + `time_stamp`: time stamp 
+ `binaries`: list of binaries

####/api/v1/detect/report/currentalertstatus
Get the current alert status from the server

*Supports*: `GET` for `/api/v1/detect/report/currentalertstatus`

#####Returns:  
`GET /api/v1/detect/report/currentalertstatus` returns a JSON object with the current alert status info

A JSON object with the current alert status info has the following structure:
+ `unresolved`: information on the unresolved alerts in the following structure:
    + `average_hours`: 
    + `alerts`: number of alerts
    + `hosts`: number of hosts
+ `resolved`:

####/api/v1/detect/report/currentmonitoringstatus
Get the current monitoring status

*Supports*: `GET` for `/api/v1/detect/report/currentmonitoring`

#####Returns:
`GET /api/v1/detect/report/currentmonitoringstatus` returns a JSON object with the current monitoring status info.

A JSON object with the current monitoring status info has the following structure:
+ `iocs`: number of indicators of compromise
+ `events_per_second`: Number of events happening per second
+ `hosts`: Number of hosts 

####/api/v1/detect/report/hosthygiene/(days)
Enumerate host hygiene over the past "days" number of days

*Supports*: `GET` for `/api/v1/detect/report/hosthygiene/(days)`

#####Returns:
+ With no "days" parameter, `GET /api/v1/detect/report/hosthygiene` returns a JSON object with the host hygiene data over the last 30 days.
+ With a "days" parameter, `GET /api/v1/detect/report/hosthygiene/days` returns a JSON object with the host hygiene data over the last "days" number of days/

A JSON object with the host hygiene data has the following structure:
+ `hygiene`: a list of the host hygiene data over the last "days" number of days, each with the following structure:  
    + `date_offset`: Number of days away from present day
    + `total_hosts`: Number of total hosts
    + `bad_hosts`: Number of bad hosts
    + `ratio`: 
    + `time_stamp`: time stamp

####/api/v1/detect/report/unresolvedalertsbyseverity/(count)/(sort) and
####/api/v1/detect/report/unresolvedalertsbytime/(count)/(sort)
Enumeration of unresolved alerts by severity score or by time. 

*Supports* `GET` for `/api/v1/detect/report/unresolvedalertsbyseverity/(count)/(sort)
*Supports* `GET` for `/api/v1/detect/report/unresolvedalertsbytime/(count)/(sort)

#####Returns:

+ With no `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedalertsbyseverity`  
returns a JSON object with the first 10 unresolved alerts by severity in descending order  
  
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedalertsbyseverity/count` returns a JSON object with the   "count" number of unresolved alerts by severity in descending order.
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedalertsbyseverity`  
returns a JSON object with the "count" number of unresolved alerts by severity in order specified by   "sort" (either ascending or descending)  

+ With no `count` or `sort` parameters, `GET /api/v1/detect/report/unresolvedalertsbytime`  
returns a JSON object with the first 10 unresolved alerts by time in descending order
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedalertsbytime/count` returns a JSON object with the   "count" number of unresolved alerts by severity in descending order.  
  
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedalertsbytime`  
returns a JSON object with the "count" number of unresolved alerts by time in order specified by   "sort" (either ascending or descending)


A JSON object of unresolved alerts has the following structure:

a list of alerts, each with structure as follows:

+ `alert_severity` : severity score of the alert
+ `created_time` : Time of creation
+ `feed_name` : Name of the feed
+ `feed_rating` : rating of the feed
+ `ioc_confidence` : Indicator of Compromise confidence score
+ `md5` : md5 hash
+ `os_type` : Operating Systems type
+ `report_score` : Score for the report
+ `sensor_criticality` : criticality score of the sensor
+ `unique_id` : id of the unresolved alert

Example:
```
GET external.carbonblack.com/api/v1/detect/report/unresolvedalertsbytime/3/asc

    [
        {
            alert_severity: 31.05
            created_time: "2014-12-26T23:12:23.369Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "96B43A7BDDEEE7DF98983B886DE56DC7"
            os_type: "windows"
            report_score: 46
            sensor_criticality: 3
            unique_id: "99140c84-55b9-4eee-aa46-658baeeacb93"
        },
        {
            alert_severity: 37.125
            created_time: "2014-12-27T00:33:06.449Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "A487BAE084BBD75ECBDC5D9FEDE362BA"
            os_type: "windows"
            report_score: 55
            sensor_criticality: 3
            unique_id: "32097e17-46c0-4ca5-bdf0-85b608edd908"
        },
        {    
            alert_severity: 44.55
            created_time: "2014-12-27T00:42:06.909Z"
            feed_name: "virustotal"
            feed_rating: 3
            hostname: ""
            ioc_confidence: 0.5
            md5: "E23DBA4B28EB7543D6D6ED5E06EEBCB6"
            os_type: "windows"
            report_score: 66
            sensor_criticality: 3
            unique_id: "a4356d81-457b-4825-8537-d662e3d04b4f"
        }
    ]
```
####/api/v1/detect/report/unresolvedalerttrend/(days)
Get trend of unresolved alerts 

*Supports*: `GET` for `/api/v1/detect/report/unresolvedalerttrend/(days)`

#####Returns:

+ With no "days" parameter, `GET /api/v1/detect/report/unresolvedalerttrend` returns a JSON object with the last 30 days worth of unresolved alerts.  

+ With a "days" parameter, `GET /api/v1/detect/report/unresolvedalerttrend/days` returns a JSON object with the last "days" days worth of unresolved alerts.  

A JSON object with past days of unresolved alerts has the following structure:

+ `counts`: a list of the unresolved alerts over the last "days" number of days. Each has the following structure:    
    + `name`: Name of the alert
    + `value`: Value of the alert
+ `start`: The start time of the trend
+ `end`: The end time of the trend

Example:
```
GET `api/v1/detect/report/unresolvedalerttrend

counts: [
          0:{
                name: "2015-05-11T00:00:00Z", 
                value: 453
            },
          1:{
                name: "2015-05-12T00:00:00Z",
                value: 450
            },
          2: {name: "2015-05-13T00:00:00Z", value: 452}
          3: {name: "2015-05-14T00:00:00Z", value: 451}
          4: {name: "2015-05-15T00:00:00Z", value: 444}
          5: {name: "2015-05-16T00:00:00Z", value: 443}
          6: {name: "2015-05-17T00:00:00Z", value: 441}
          7: {name: "2015-05-18T00:00:00Z", value: 451}
          8: {name: "2015-05-19T00:00:00Z", value: 447}
          9: {name: "2015-05-20T00:00:00Z", value: 445}
          10: {name: "2015-05-21T00:00:00Z", value: 444}
          11: {name: "2015-05-22T00:00:00Z", value: 449}
          12: {name: "2015-05-23T00:00:00Z", value: 444}
          13: {name: "2015-05-24T00:00:00Z", value: 448}
          14: {name: "2015-05-25T00:00:00Z", value: 447}
          15: {name: "2015-05-26T00:00:00Z", value: 450}
          16: {name: "2015-05-27T00:00:00Z", value: 453}
          17: {name: "2015-05-28T00:00:00Z", value: 449}
          18: {name: "2015-05-29T00:00:00Z", value: 449}
          19: {name: "2015-05-30T00:00:00Z", value: 448}
          20: {name: "2015-05-31T00:00:00Z", value: 443}
          21: {name: "2015-06-01T00:00:00Z", value: 451}
          22: {name: "2015-06-02T00:00:00Z", value: 452}
          23: {name: "2015-06-03T00:00:00Z", value: 453}
          24: {name: "2015-06-04T00:00:00Z", value: 448}
          25: {name: "2015-06-05T00:00:00Z", value: 451}
          26: {name: "2015-06-06T00:00:00Z", value: 463}
          27: {name: "2015-06-07T00:00:00Z", value: 443}
          28: {name: "2015-06-08T00:00:00Z", value: 452}
          29: {name: "2015-06-09T00:00:00Z", value: 452}
          30: {name: "2015-06-10T00:00:00Z", value: 445}
        ]
end: "2015-06-11T00:00:00Z"
start: "2015-05-11T00:00:00Z"
```
####/api/v1/detect/report/unresolvedhostsbyseverity/(count)/(sort) and
####/api/v1/detect/report/unresolvedhostsbytime/(count)/(sort)
Enumeration of unresolved hosts by severity score or by time. 

*Supports* `GET` for `/api/v1/detect/report/unresolvedhostsbyseverity/(count)/(sort)
*Supports* `GET` for `/api/v1/detect/report/unresolvedhostsbytime/(count)/(sort)

#####Returns:

+ With no `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedhostsbyseverity`  
returns a JSON object with the first 10 unresolved hosts by severity in descending order  
  
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedhostsbyseverity/count` returns a JSON object with the   "count" number of unresolved hosts by severity in descending order.
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedhostsbyseverity`  
returns a JSON object with the "count" number of unresolved hosts by severity in order specified by   "sort" (either ascending or descending)  

+ With no `count` or `sort` parameters, `GET /api/v1/detect/report/unresolvedhostsbytime`  
returns a JSON object with the first 10 unresolved hosts by time in descending order
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedhostsbytime/count` returns a JSON object with the   "count" number of unresolved hosts by severity in descending order.  
  
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedhostsbytime`  
returns a JSON object with the "count" number of unresolved hosts by time in order specified by   "sort" (either ascending or descending)

A JSON object of unresolved hosts has the following structure:

a list of hosts, each with structure as follows:
+ `average_hours`: average hours
+ `os_type`: Type of Operating System
+ `hostname`: Name of the host

Example:
```
GET /api/v1/detect/report/unresolvedhostsbytime

[
    {
        average_hours: 38.0774272779,
        os_type: "windows",
        hostname: ""
    },
    {
        average_hours: 43.1798545668, 
        os_type: "Windows", 
        hostname: "constantine-hp"
    },
]
```
####/api/v1/detect/report/unresolvedusersbyseverity/(count)/(sort) and
####/api/v1/detect/report/unresolvedusersbytime/(count)/(sort)
Enumeration of unresolved users by severity score or by time. 

*Supports* `GET` for `/api/v1/detect/report/unresolvedusersbyseverity/(count)/(sort)
*Supports* `GET` for `/api/v1/detect/report/unresolvedusersbytime/(count)/(sort)

#####Returns:

+ With no `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedusersbyseverity`  
returns a JSON object with the first 10 unresolved users by severity in descending order  
  
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedusersbyseverity/count` returns a JSON object with the   "count" number of unresolved users by severity in descending order.
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedusersbyseverity`  
returns a JSON object with the "count" number of unresolved users by severity in order specified by   "sort" (either ascending or descending)  

+ With no `count` or `sort` parameters, `GET /api/v1/detect/report/unresolvedusersbytime`  
returns a JSON object with the first 10 unresolved users by time in descending order
+ With a `count` parameter and no `sort` parameter  
`GET /api/v1/detect/report/unresolvedusersbytime/count` returns a JSON object with the   "count" number of unresolved users by severity in descending order.  
  
+ With `count` and `sort` parameters, `GET /api/v1/detect/report/unresolvedusersbytime`  
returns a JSON object with the "count" number of unresolved users by time in order specified by   "sort" (either ascending or descending)




####/api/tagged_event/(id)
Enumeration, addition, deletion, and updating of tagged_events associated with an investigation

*Supports* `GET`, `PUT`, and `DELETE` for `/api/tagged_event/<id>`  
*Supports* `POST` for `/api/tagged_event`

#####Returns:

+ With no "id" parameter, `POST /api/tagged_event` returns whether or not the posting attempt was successful
+ With an "id" parameter, `GET /api/tagged_event/id` returns a JSON object with the structure of the tagged_events of the investigation with id "id"
+ With an "id" parameter, `PUT /api/tagged_event/id` returns whether or not the updating attempt was successful
+ With an "id" parameter, `DELETE /api/tagged_event/id` returns whether or not the deleting attempt was successful

A JSON object of events has the following structure:
+ a list of events, each with the following structure:
    + `date_tagged`: the date the event was tagged
    + `event_data`: the data for this tagged_event
    + `event_id`: the event id
    + `event_type`: type of the event
    + `id`: the investigation id of the event
    + `investigation_id`: the investigation id this event is associated with
    + `process_id`: id of the process that this event is under
    + `segment_id`: id of the segment of the server this event is in
    + `start_date`: date to start monitoring for the event
    + `tagged_by_user_id`: id of the user to tag the event
    + `unique_id`: unique id of the event

Example:
```
GET /api/tagged_event/1

[
    {
        date_tagged: "2015-06-12 11:53:30.175373-04:00"
        event_data: "{"description": "Testing event addition"}"
        event_id: null
        event_type: null
        id: 8
        investigation_id: 1
        process_id: null
        segment_id: 0
        start_date: "2015-06-03 20:00:00-04:00"
        tagged_by_user_id: null
        unique_id: null
    }
]

####








 
























































