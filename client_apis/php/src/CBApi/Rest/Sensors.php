<?php

namespace CBApi\Rest;

/**
 * Class Sensors
 *
 * @package CBApi\Rest
 */
class Sensors
{
    /** @var array */
    private static $sensors = [
        'WindowsEXE' => '/api/v1/group/{group_id}/installer/windows/exe',
        'WindowsMSI' => '/api/v1/group/{group_id}/installer/windows/msi',
        'OSX'        => '/api/v1/group/{group_id}/installer/osx',
        'Linux'      => '/api/v1/group/{group_id}/installer/linux'
    ];

    /**
     * @return array
     */
    public static function getSensors()
    {
        return self::$sensors;
    }

    /**
     * @param $group_id
     * @return array
     */
    public static function getSensorMapping($group_id)
    {
        return array_map(
            function ($url) use ($group_id) {
                return str_replace('{group_id}', $group_id, $url);
            },
            self::getSensors()
        );
    }
}
