<?php

namespace CBApi\Exception;

use CBApi\Rest\Sensors;

/**
 * Class InvalidSensorException
 *
 * @package CBApi\Exception
 */
class InvalidSensorException extends \Exception
{
    /**
     * @param string $type
     */
    public function __construct($type)
    {
        $sensors = implode(', ', array_keys(Sensors::getSensors()));
        parent::__construct(
            sprintf("Invalid sensor %s, should be one of {$sensors}", $type)
        );
    }
}
