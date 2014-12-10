Carbon Black Live Response Sensor API 
=========================

https://www.bit9.com/solutions/carbon-black/

## CB Live Response Sensor API

### Reference Implementation

The Carbon Black API is a RESTful API and can be consumed by practically any language.  An example pseudo-shell script, similar to the Web UI shell, is included here for reference purposes. 

### Authentication

The Sensor API is a subset of the broader Cb Client REST APIs.  Authentication uses the same [AuthToken Header described there](https://github.com/carbonblack/cbapi/tree/master/client_apis#api-authentication).

### Sessions

All Live Response APIs require you to first establish a "session" with a sensor. A sensor with an active session will keep an open connection to the Carbon Black server for as long as the session is active. All Live Response command APIs require a session id.

## Example

#### Start a new session
All CBLR activity requires you first start a session with a sensor by `POST`ing to `/api/v1/cblr/session` with requested sensor_id.  For example:

```
[root@guy-cbdev-6 ~]# curl -H "Content-Type: application/json" -H "X-Auth-Token: d91b00774b2b903b49d8d9caa57ce9fcde16973a" -d '{"sensor_id": 10}' http://127.0.0.1/api/v1/cblr/session
{"status": "pending", "sensor_id": 10, "supported_commands": [], "drives": [], "storage_size": 0, "create_time": 1418247933.634789, "sensor_wait_timeout": 120, "address": null, "check_in_timeout": 1200, "id": 2, "hostname": "WIN-EP7RMLTCLAJ", "storage_ttl": 7, "os_version": "", "session_timeout": 300, "current_working_directory": ""}
```
Note `status` is pending and the session id is 2.   Wait a few seconds, then `GET` status of session 2:

```
[root@guy-cbdev-6 ~]# curl -H "Content-Type: application/json" -H "X-Auth-Token: d91b00774b2b903b49d8d9caa57ce9fcde16973a" http://127.0.0.1/api/v1/cblr/session/2
{"status": "active", "sensor_id": 10, "supported_commands": ["delete file", "put file", "reg delete key", "directory list", "reg create key", "get file", "reg enum key", "reg query value", "kill", "create process", "process list", "reg delete value", "reg set value", "create directory"], "drives": ["A:\\", "C:\\", "D:\\"], "storage_size": 0, "create_time": 1418247933.634789, "sensor_wait_timeout": 120, "address": "::ffff:192.168.206.128", "check_in_timeout": 1200, "id": 2, "hostname": "WIN-EP7RMLTCLAJ", "storage_ttl": 7, "os_version": "", "session_timeout": 300, "current_working_directory": "C:\\Windows\\CarbonBlack"}
```
Note `status` is active and session object now has context from the endpoint - `supported_commands`, `current_working_directory`, etc.   
#### Issue command
Once a session is active, you can create commands by `POST`ing a command object to the session via  `/api/v1/cblr/session/2/command`. For example, to get a process list:

```
[root@guy-cbdev-6 ~]# curl -H "Content-Type: application/json" -H "X-Auth-Token: d91b00774b2b903b49d8d9caa57ce9fcde16973a" -d '{"session_id": 2, "name": "process list"}' http://127.0.0.1/api/v1/cblr/session/2/command
{"status": "pending", "username": "admin", "sensor_id": 10, "create_time": 1418248098.5540111, "name": "process list", "object": null, "id": 1, "session_id": 2}
```

Note `status` is pending and command id is 1.   Wait a few seconds, then `GET` status of command 1 in session 2:

```
[root@guy-cbdev-6 ~]# curl -H "Content-Type: application/json" -H "X-Auth-Token: d91b00774b2b903b49d8d9caa57ce9fcde16973a" http://127.0.0.1/api/v1/cblr/session/2/command/1
{"status": "complete", "username": "admin", "sensor_id": 10, "object": null, "create_time": 1418248098.5540111, "id": 1, "completion": 1418248098.5710759, "processes": [{"username": "NT AUTHORITY\\SYSTEM", "create_time": 1418247141, "parent_guid": "0000000a-0000-0000-0000-000000000000", "parent": 0, "sid": "s-1-5-18", "path": "", "command_line": "", "pid": 4, "proc_guid": "0000000a-0000-0004-01d0-14c0c80ce18b"}, {"username": "NT AUTHORITY\\SYSTEM", "create_time": 1418247141, "parent_guid": "0000000a-0000-0004-01d0-14c0c80ce18b", "parent": 4, "sid": "s-1-5-18", "path": "c:\\windows\\system32\\smss.exe", "command_line": "\\systemroot\\system32\\smss.exe", "pid": 276, "proc_guid": "0000000a-0000-0114-01d0-14c0c80f42ec"}, ... }
```
Note `status` is complete and the response includes a `processes` object that contains the list of currently running processes on sensor_id 10 WIN-EP7RMLTCLAJ.   

Other commands function broadly the same way.   See the documentation below and the python reference implementation for details.   Happy hunting!

## API Summary

### Sessions

- [`/api/v1/cblr/session/(id)`](#apiv1cblrsessionid) - Manage current sessions
- [`/api/v1/cblr/session/(id)/keepalive`](#apiv1cblrsessionidkeeaplive) - Send keepalive for specified session
- [`/api/v1/cblr/session/(id)/archive`](#apiv1cblrsessionidarchive) - Download complete session log as a compressed archive

### Commands 

- [`/api/v1/cblr/session/(id)/command`](#apiv1cblrsessionidcommand) - Create new command, list current commands
- [`/api/v1/cblr/session/(id)/command/(cmd_id)`](#apiv1cblrsessionidcommandcmdid) - Get command result or cancel pending command

### Files

- [`/api/v1/cblr/session/(id)/file/(file_id)`](#apiv1cblrsessionidfilefileid) - Return file metadata for one or all files downloaded
- [`/api/v1/cblr/session/(id)/file/(file_id)/content`](#apiv1cblrsessionidfilefile_id/content) - Return file bytes for specified file

## Built-in Command Summary

- [Command Request Objects](#command-requests) - JSON objects for requesting command
- [Command Response Objects](#command-responses) - JSON objects for each command result

## API Reference

#### `/api/v1/cblr/session/(id)`

*Supports*: `GET`, `POST`
- `GET` - returns a list of all current session objects
- `GET` - with (id) - returns a single session object if it exists
- `POST` - starts a new session (given a sensor id), returns a session id

##### URL Parameters:
- `wait`: OPTIONAL True/False - Blocks the response until a session is available.

##### GET returns:
Returns `cblr_sensor` session object with the following elements:

- `id`: the current session id
- `sensor_id`: the sensor id for this session
- `status`:  The current sensor live response status (“active”, “pending”, “timeout”, “inactive”, “close”)  - Set status to close and PUT the object to close out the session
- `os_version`: The current OS version of the sensor
- `current_working_directory`:  The path to the current working directory of the sensor
- `drives`: An array of the logical drives available on the system
- `supported_commands`:  An array listing out the supported commands on the sensor (for when we support multiple commands across different architectures.  (Note: These are 1:1 mapped with the name in the JSON command object (below))
- `check_in_timeout`: the timeout (in seconds) - how long should the CB server wait for the sensor to enter live mode (check-in) (default is wait 1200 seconds - 20 minutes)
- `session_timeout`: the timeout (in seconds) that a sensor should wait between commands.   If no command is issued over this timeout the sensor will quit.  By default this is 8 minutes

#### POST accepts:
The POST request accepts the following fields in a JSON payload:

- `sensor_id` - the sensor id to start the session for
- `checkin_timeout` (optional) (see cblr_sensor)
- `default_command_timeout` (optional) (see cblr_sensor)
- `sensor_wait_timeout` (optional) (see cblr_sensor)

POST returns JSON “cblr_sensor” (see above) _Note:_ only the id will be set in the cblr_sensor until the session has checked in.

#### `/api/v1/cblr/session/(id)/keepalive`

*Supports*: `GET`

This doesn’t take an parameters but simply tells the server to reset the sensor “sensor_wait_timeout” if no commands have been sent to the sensor.  This should be leveraged by interactive processes to keep a session alive when there is no command activity past the “sensor_wait_timeout” period.   A request to the endpoint should be made in a time period less than the sensor_wait_timeout time.

#### `/api/v1/cblr/session/(id)/archive`
*Supports:* `GET`

Returns a compressed archive of all the session contents: log of all commands, their results, contents of all files, etc.

#### `/api/v1/cblr/session/(id)/command`
*Supports*: `GET`, `POST`
- `GET` - returns a list of commands in this session
- `POST` - creates a new command for this session

##### URL Parameters:
- `status`: OPTIONAL completed/in progress/canceled - filter results based on command status
- `count`: OPTIONAL int - limit to X results returned

See [Command Objects](#command-objects) below for command object details.

#### `/api/v1/cblr/session/(id)/command/(cmdid)`
*Supports*: `GET`, `PUT`
- `GET` - with (cmdid) - returns the status for the specified command
- `PUT` - with (cmdid) - cancel the specified command if status is `pending`

See [Command Objects](#command-objects) below for command object details.

#### `/api/v1/cblr/session/(id)/file/(file_id)`
*Supports*: `GET`, `PUT`
- `GET` - returns a list of files for this session
- `GET` - with (file_id) - returns the `file` object for the specified id
- `PUT` - with (file_id) -  deletes a file object from the server
- `DELETE` - with (file_id) - deletes a file object from the server
)
##### GET returns:
Returns a `file` object with the following fields:
- `id`: the file id
- `file_name` : the (remote) path of the file
- `size` : the size of the file
- `size_uploaded` : the size of the full uploaded (from the sensor) so far
- `status`: A status code, result for the file request.  0 for success or non-zero for error.
- `delete` : By default this is “false”,  (on PUT) set to “true” to force file deletion

`PUT` this object with `delete` set to true or use the DELETE HTTP verb to delete a file from the server's store.

#### `/api/v1/cblr/session/(id)/file/(file_id)/content`
*Supports:* `GET`

Return the raw contents of the specified file.


## Command Objects

### Command Requests

The contents of the command request object will vary based on the command requested and the context.    Fields present in all command objects:

- `id`: id of this command
- `session_id`: the id of the session
- `sensor_id`: the sensor id for the session
- `command_timeout`: the timeout (in seconds) that the sensor is willing to wait until the command completes.
- `status`: One of the following: “in progress”, “complete”, “cancel”, “error” 
- `name`:  The name of the command (ie “reg set”, “reg query”, “get file”....)
- `object`: the object the command operates on.  This is specific to the command but has meaning in a generic way for logging, and display purposes

Fields present when command completes:

- `completion_time`:  the time the command completed or 0 if still in progres

These are present if “error” is set in the status. 

- `result_code`: the result/status (0 if successful) or an error code if unsuccessful
- `result_type`: “WinHresult”, “CbError”, etc
- `result_desc`: Optional error string describing the error

The remaining fields are specific to each requested built-in command:

#### put file:
- `name`: “put file”
- `object`: the destination path of the file 
- `file_id`: the file id of the file in session storage (use second api to add new files)

#### get file:
- `name`: “get file”
- `object`: the source path of the file
- `offset`: a byte offset to start getting the file.  Supports a partial get.
- `get_count`:  the number of bytes to grab 

#### delete file:
- `name`: “delete file”
- `object`: the source path of the object to delete

#### directory listing:
- `name`: “directory list”
- `object`: the directory listing filter (or path)

#### reg enum key:
- `name`: “reg enum key”
- `object`: the path of the key to query

#### reg query value:
- `name`: “reg query value”
- `object`: the path of the key + the path of the value (ie HKEY_LOCAL_MACHINE\blah\key\value)

#### reg create key:
- `name`: “reg create key”
- `object`:  the key path to create

#### reg delete key:
- `name`: “reg delete key”
- `object`:  the key path to delete

#### reg delete value:
- `name` : “reg delete value”
- `object`: the path of the key + the path of the value

#### reg set value:
- `name`: “reg set value”
- `object`: the path of the key + the path of the value
- `value_data`: the data to set for the value.  Note if value_data is for type REG_MULTI_SZ then value_data should be an array of strings.  ie “value_data” : [“string1”, “string2”, “string3”], 
- `value_type`: one of common reg value types (in string form).   Ie REG_DWORD, REG_QWORD, REG_SZ, …..
- `overwrite`: “true” or “false”.  An optional parameter to specify whether to overwrite the value if it already exists (default value is “false”)

#### ps
- `name`: “process list”
- `object`: empty

#### kill
- `name`: “kill”
- `object`: the pid to kill

#### execute
- `name`: “create process”
- `object`: the path and command line of the executable
- `wait`: “true” or “false” - An optional parameter to specify whether to wait for the process to complete execution before reporting the result 
- `working_directory`: An optional parameter to specify the working directory of the executable
- `output_file`: An option file that STDERR and STDOUT will be redirected to.

### Command results

The command result object contents vary per built-in command.

#### directory listing: 
- `files`: an array of file list objects, which contain:
  - `attributes`: an array of attribute strings representations of windows file attributes, with the FILE_ATfTRIBUTE_ part removed (ie DEVICE, DIRECTORY, HIDDEN, …..)
  - `create_time`: in unix time format
  - `last_access_time`: in unix time format
  - `last_write_time`: in unix time format
  - `size`: the size of the file 
  - `name`: the name of the file
  - `alt_name`: the Windows “alternate name” (short name) of the file

#### execute:
- `pid`: the pid of the executed process 
- `return_code`: the return code of the process (if wait was set to “true”)

#### process list:
- `processes`: an array of process objects which contain:
- `pid`: process id
- `create_time`: the creation time of the process in unix time
- `proc_guid`: the process guid of the process
- `path`: the execution path of the process
- `command_line`: the command line of the process
- `sid`: the Security Identifier (SID) of the default process token 
- `username`: the username of the default process token
- `parent`: the pid (process id ) of the parent
- `parent_guid`: the process guid of the parent process

#### get file:
- `file_id`: the file id of the file (must use second API call to obtain the file)

#### reg enum key:
- `values`: an array of registry values which contain:
  - `value_type`: the string representation of the registry value type (ie REG_DWORD, REG_QWORD, ….)
  - `value_name`: the name of the registry value
  - `value_data`: the data associated with the registry value
  - sub_keys : an array of subkey names  (ie { “sub_keys” : [“some_sub_key” ,  “some_other_sub_key”]}

#### reg query value:
 - `value`: See the values object returned in the “values” field of reg enum key
