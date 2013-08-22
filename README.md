Carbon Black Enterprise Server
=========================

http://carbonblack.com

## REST API

### Versioned 

The following APIs are versioned.  Backwards compatability will be maintained for at most two major version revisions. 

``` None yet. Final APIs expected early Q413. ```

### Beta

The following APIs are *beta*.  The interfaces will change and backwards compatibility will not be supported.   The underlying data is not expected to substantially change.

#### Search
[`/api/search`](#apisearch) - Process search

## API Listing

####  `/api/search/`
Process search.  Parameters passed as a query string.

##### Parameters:
- REQUIRED `q`: Query string. Accepts the same data as the search box on the Process Search page.  `TODO`: link to query syntax doc
- OPTIONAL `rows`: Return this many rows, 10 by default.
- OPTIONAL `start`: Start at this row, 0 by default.
- OPTIONAL `sort`: Sort rows by this field.  `last_update` by default.
- OPTIONAL `facets`: Return facet results.  'false' by default, set to 'true' for facets.

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
http://192.168.206.151/api/search/?q=notepad.exe

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
        "52af8b63-8fb4-e30d-0000-000000000001"
      ]
    }, 
  ]
  "tagged_pids": {  }, 
  "filtered": {}, 
}
```
