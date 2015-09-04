## CarbonBlack PHP API
[![Build Status](https://travis-ci.org/javabudd/CbApi.svg?branch=master)](https://travis-ci.org/javabudd/CbApi)

```php
$api = new \CBApi\Api('https://localhost', 'XXXXXXXXXXXXXXXXXXXXXXXXXX');

/** Get */
$api->get()->info();
$api->get()->processSearch('process_name:svchost.exe -path:c:\\windows\\');
$api->get()->sensorInstaller('WindowsEXE');

/** Put */
$api->put()->license(XXXXXXXXXXXXXXXXXXXXX);
$config = array('username' => 'example', 'password' => 'example', 'server' => 'localhost');
$api->put()->platformServerConfig($config);
```
