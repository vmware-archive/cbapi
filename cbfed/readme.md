# CB Fed API

### User API:

`/api/v1/cbfed/user`
*Supports*:: [`GET`, `POST`]
* `GET` - Returns a list of [CB Fed User Objects](#cb-fed-user-object)
* `POST` - Adds a new [CB Fed User Object](#cb-fed-user-object) (with blank userid)
 - Requires Admin privileges

`/api/v1/cbfed/user/{ID}`
*Supports*:: [`GET`, `PUT`, `DELETE`]
* `GET` - Returns a specific [CB Fed User object](#cb-fed-user-object). 
 - api_token is only returned if user is admin or self.
* `PUT` - Changes a specific [CB Fed User object](#cb-fed-user-object)
 - Requires Admin privileges or change of self
 - Requires Admin privileges to set “admin” property. 
 - Requires admin or self to set “reset_api_token”
* `DELETE` - Deletes a specific [CB Fed User object](#cb-fed-user-object)
 - Requires admin privileges
 - Cannot delete self.

#####CB Fed User Object
```
{
"id" : An internal ID to identify the user (int)
"username" : The username of the user (string)
"first_name" : The first name of the user (string)
"last_name" : The last name of the user (string)
"is_admin" : If the user is an admin or regular user (boolean)
"password" : (Only for POST/PUT) - The new password for the user (string)
"api_token" : (Only on GET) - Only populated if user is self or admin (string)
"reset_api_token" : (Only on PUT) - If set to true the API token will be reset for the user (boolean)
}
```

### Cluster API:

`/api/v1/cbfed/cluster`
*Supports*:: [`GET`, `POST`]
* `GET` - Returns a list of the [CB Fed Cluster Objects](#cb-fed-cluster-object)
* `POST` - Adds a new cluster to the federation. Returns [CB Fed Cluster Objects](#cb-fed-cluster-object) for the added cluster
 - Requires admin

`/api/v1/cbfed/cluster/{ID}`
*Supports*:: [`GET`, `PUT`, `DELETE`]
* `GET` - Returns [CB Fed Cluster Object](#cb-fed-cluster-object) for the cluster 
* `PUT` - Changes the cluster. Returns [CB Fed Cluster Objects](#cb-fed-cluster-object) for an updated cluster.
 - Requires admin privileges
* `DELETE` - Deletes the cluster from the federation. Returns `{"result":"success"}` if sucessfully deleted.
 - Requires admin privileges

`/api/v1/cbfed/cluster_user_settings`
*Supports*:: [`GET`]
* `GET` - Returns an array of [CB Fed Per User Cluster Settings Objects](#cb-fed-per-user-cluster-settings-object) for all clusters for the current user

`/api/v1/cbfed/cluster/{ID}/user_settings`
*Supports*:: [`GET`, `PUT`]
* `GET` - Returns a [CB Fed Per User Cluster Settings Object](#cb-fed-per-user-cluster-settings-object) for the current user
* `PUT` - Change the settings on a cluster

`/api/v1/cbfed/cluster/{ID}/stats`
*Supports*:: [`GET`]
* `GET` - Returns an array [CB Fed Cluster Stats Objects](#cb-fed-cluster-stats-object) for the cluster

`/api/v1/cbfed/cluster/{ID}/stats/summary[?limit=0]`
*Supports*:: [`GET`]
* `GET` - Returns one [CB Fed Cluster Stats Object](#cb-fed-cluster-stats-object) which is an aggregation of `limit=X` stats objects starting from the most recent. `limit=0` aggregates over the entire set. If limit is not provided then `limit=0` is used.

`/api/v1/cbfed/cluster/{ID}/errorlogs`
*Supports*:: [`GET`]
* `GET` - Returns an array of last 50 [ErrorLog Objects](#errorlog-object). 50 is controlled via configuration file.


`/api/v1/cbfed/cluster/{ID}/errorlogs/export`
*Supports*:: [`GET`]
* `GET` - Returns a csv file with last 50 errors

##### CB Fed Cluster Object
```
{
"id" : An internal ID to identify the cluster (int)
"name" : A (short/terse) user defined name for the cluster (string)
"description" : A detailed name/description of the cluster (string)
"url" : The URL for the cluster (string)
"using_shared_token" : Is there a shared token for this cluster (boolean)
"shared_token" : The shared token for the cluster (string). Only populated if user is admin.  Set to “” (empty string to clear it out)
"disabled" : Stop making queries to this cluster. Applies to all users. (boolean)  
"verify_ssl" : Whether or not to ignore SSL certificate errors when making requests to the cluster (boolean)
"last_heartbeat_time" : The time (in unix time in GMT time) of the last successful heartbeat
"status" : A descriptive string describing the status (OPERATIONAL|UNSTABLE|UNAVAILABLE)
}
```

##### CB Fed Per User Cluster Settings Object
```
{
"disabled" : Is this cluster disabled from queries (only applies to this user) (boolean)
"user_token" : A per-user authentication token for the cluster.  Set to “” to clear
}
```

##### CB Fed Cluster Stats Object
```
{
"max_query_time" : Max query time to the cluster in seconds (float)
"avg_query_time" : The average query time to the cluster in seconds (float)
"avg_round_trip_time" : The average time to perform a “heartbeat” query against the cluster in seconds (float)
"last_request_time" : The time (unix time in GMT) since the last request.
"last_success_time" : The time (unix time in GMT) since the last success query.
"last_failure_time" : The time (unix time in GMT) since the last failure.
"last_timeout_time" : The time (unix time in GMT) since the last time out.
"created_time" : The time (unix time in GMT) when stats object was created.
"request_count" : The total number of queries made against the cluster
"success_count" : The total number of successful queries made against the cluster
"failure_count"  : The total number of failed queries made against the cluster
"timeout_count"  : The total number of timedout queries made against the cluster
"round_trip_count"  : The total number of health check queries made against the cluster
}
```

```
{
cluster_id : 1
max_query_time : 0.029401
avg_query_time : 0.029401
avg_round_trip_time : 0.019401
request_count: 2
success_count: 1
failure_count : 0
timeout_count : 0
round_trip_count : 1
last_success_time : "2015-08-07T16:53:49.560175"
last_request_time : "2015-08-07T16:53:49.560175"
last_timeout_time : null
last_failure_time : null,
created_time : "2015-08-07T16:53:49.560175"
}
```

##### ErrorLog Object:
```
{
"cluster_id": id of the cluster
"method": HTTP method,
"url": url,
"data":data of the call. dict with all post values,
"message": Error message,
"status_code": status_code,
"request_time": time at what request was made
}
```

### Error handling:
In case of an error on the federation server [Cb Fed Exception](#cb-fed-exception) is returned to the client.

##### Cb Fed Exception:
```
{
"message": error message in free text form (string)
"error": one of the Cb Fed Error Enum values (string),
"error_code": Cb Fed Error Enum integer value (integer) ,
"status_code": HTTP status code. Can be different from error_code if match to Cb Fed Error was not found.
  Response status code is set to this value (integer),
"payload": Additional payload if the exception was thrown on the cb cluster side and just being propogated through fed. (string)
}
```

##### Cb Fed Error
```python
class Error(IntEnum):
    NoContent = 204 #sent if there is no content to sent. For instance, DELETE of the user already deleted.
    InvalidParameter = 400 #thrown if the parameter for the call is invalid
    InvalidCredentials = 401 #thrown when authentication credentials are invalid.
    InsufficientPermissions = 403 #thrown when user is not authorized to do a call
    ResourceNotFound = 404
    InvalidOperation = 405 # thrown when the action can not be performed. E.g. user tries to delete himself
    Timeout = 408
    Conflict = 409 # Returned by the cluster sometimes
    AccountLocked = 423 # Too many attempts to login.
    InternalServerError = 500, #Generic error
    BadGateway = 502, # Error code is used when cluster can not be accessed because of the 502 error
    ServiceUnavailable = 503, # Error code is used when cluster can not be accessed because of the 503 error
    GatewayTimeout = 504, # Error code is used when cluster can not be accessed because of the 504 error
    NetworkConnectTimeoutError = 599 # Error code is used when no connection can be established at all.
       Reasons: ConnectionError
                ProxyError
                URLRequired
                MissingSchema
                InvalidSchema
                InvalidURL
                ChunkedEncodingError
                ContentDecodingError
                StreamConsumedError
                ConnectTimeout

```
