Carbon Black Enterprise Server
=========================

http://carbonblack.com

## REST API

### Versioned 

The following APIs are versioned.  Backwards compatability will be maintained for at least two major version revisions. 

``` None yet. Final APIs expected early Q413. ```

### Beta

The following APIs are *beta*.  The interfaces will change and backwards compatibility will not be supported.   The underlying data is not expected to substantially change.

#### Search
- [`/api/search`](#apisearch) - Process search
- [`/api/search/module`](#apisearchmodulequery) - Binary search

#### Process Data 
- [`/api/process/`](#apiprocessidsegment) - Process summary data
- [`/api/events/`](#apieventsidsegment) - Events for the selected process
 
## API Listing

####  `/api/search/`
Process search.  Parameters passed as a query string.

##### Parameters:
- `q`: REQUIRED Query string. Accepts the same data as the search box on the Process Search page.  `TODO`: link to query syntax doc
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
- `start`: the start time of the process in remote computer's GMT time
- `last_update`: the time of the most recently received event for this process in remote computer's GMT time
- `hostname`: the hostname of the computer for this process
- `modload_count`: the count of modules loaded in this process
- `regmod_count`: the count of registry modifications in this process
- `filemod_count`: the count of file modifications in this process
- `netconn_count`: count of network connections in this process
- `childproc_count`: the count of child processes launched by this process
- `group`: the CB Host group this sensor is assigned to 
- `sensor_id`: the internal CB id for this computer's sensor
- `id`: the internal CB process GUID for this process (processes are identified by this GUID and their segment id)
- `segment_id`: the process segment id (processes are identified by this segment id and their process ID id)
- `unique_id`: internal CB process id combining of the process GUID and segment GUID

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
- `percent`: the ratio of this value to the total set of values in the result set

A complete example:

```
GET http://192.168.206.151/api/search/?q=notepad.exe

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
      "childproc_count": 7
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

####  `/api/search/module/<query>`
Binary search.  Parameters passed as in URL path.

##### Parameters:
- `q`: REQUIRED Query string. Accepts the same data as the search box on the Binary Search page.  `TODO`: link to query syntax doc
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
- `server_added_timestamp`: the first time this binary was received on the server in the server's GMT time
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
GET http://192.168.206.151/api/search/module/q=notepad.exe

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
      "file_desc": "Notepad"
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

####  `/api/process/(id)/(segment)`
Gets basic process information for segment (segment) of process (guid)

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


A complete example:

```
GET http://192.168.206.154/api/process/2032659773721368929/1

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
    "id": "2032659773721368929"
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
      "id": "5286285292765095481"
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
    "id": "5856845119039539348"
  }
}
```

#### `/api/events/(id)/(segment)/`
Gets the events for the process with id (id) and segment (segment)

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
GET http://192.168.206.154/api/events/2032659773721368929/1

{"process": 
  {"process_md5": "517110bd83835338c037269e603db55d", 
  "sensor_id": 2, 
  "group": "Default Group", 
  "start": "2013-09-19T22:07:07Z",
  "process_name": "taskhost.exe", 
  "segment_id": 1, 
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
