# Carbon Black API 

## License

Use of the Carbon Black API is governed by the license found in LICENSE.md.

## Overview

Carbon Black includes extensive support for programmatic access to the underlying data and configuration via APIs.

There are three primary APIs:

* Carbon Black Client API (CBCAPI)
* Carbon Black Server API (CBSAPI)
* Carbon Black Feed API (CBFAPI)

### Carbon Black Client API
*Introduced in v3.0*

The Carbon Black Client API (CBCAPI) is found on github at:

  https://github.com/carbonblack/cbapi/tree/master/client_apis

The CBCAPI is a collection of documentation, example scripts, and a helper library to allow for querying the backend data store and getting and setting configuration.  This is the same API that the Carbon Black web console uses to interface with the Carbon Black server.

### Carbon Black Server API
*Introduced in v4.2*

The Carbon Black Server API (CBSAPI) is found on github at:

  https://github.com/carbonblack/cbapi/tree/master/server_apis

The CBSAPI is a collection of documentation, example scripts, and a helper library to help subscribe to Carbon Black server notifications, parse and understand the contents of those notifications, and demonstrate common business logic uses of those notifications.

### Carbon Black Sensor API
*Introduced in v5.0*

  https://github.com/carbonblack/cbapi/tree/master/sensor_apis

The Carbon Black Live Response Sensor API allows incident responders to automate investigation and triage activities on any Windows endpoint with the v5.0+ sensor installed.  The API includes a number of built-in functions, including bidirectional file transfer and process execution.  Upload yara and search for signatures or upload your own Powershell scripts to run scripted actions locally.  It does not matter where the sensor is currently located - inside the corporate LAN or at Starbucks, if the sensor is pushing data to the Carbon Black server, the Sensor API can be used for investigations.

### Carbon Black Feed API
*Introduced in v4.0*

The Carbon Black Feed API (CBFAPI) is found on github at:

  https://github.com/carbonblack/cbfeeds

The CBFAPI is a collection of documentation, example scripts, and a helper library to help build and validate Carbon Black feeds.

## Versioning

The Carbon Black API is versioned.  A new API revision is released in lockstep with each release of the Carbon Black Enterprise Server.

Previous version documentation can be found using git tags.
