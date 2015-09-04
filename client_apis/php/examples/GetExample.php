<?php

/**
 * Example Get Requests
 */

include __DIR__ . '/../vendor/autoload.php';

$api = new \CBApi\Api('https://localhost', 'e498d97b3c32541e4ba5b537e0a7e61cfa14c089');

echo $api->get()->info();
echo $api->get()->processSummary(1, 1);
echo $api->get()->sensorInstaller('WindowsEXE');

