<?php

namespace CBApi;

use CBApi\Rest\GetRest;
use CBApi\Rest\PutRest;
use CBApi\Connection\Request;

include __DIR__ . '/../../vendor/autoload.php';

/**
 * Class Api
 * @package Api
 */
class Api
{
    /** @var GetRest */
    private $getRest;

    /** @var PutRest */
    private $putRest;

    /** @var Request */
    private $request;

    /** @var string */
    private $api_url;

    /** @var string */
    private $api_key;

    /**
     * @param $api_url
     * @param $api_key
     */
    public function __construct($api_url, $api_key)
    {
        $this->api_url = $api_url;
        $this->api_key = $api_key;
    }

    /**
     * @return GetRest
     */
    public function get()
    {
        if (null === $this->getRest) {
            $this->getRest = new GetRest($this->getRequestObj());
        }

        return $this->getRest;
    }

    /**
     * @return PutRest
     */
    public function put()
    {
        if (null === $this->putRest) {
            $this->putRest = new PutRest($this->getRequestObj());
        }

        return $this->putRest;
    }

    /**
     * @return Request
     */
    private function getRequestObj()
    {
        if (null === $this->request) {
            $this->request = new Request($this->api_url, $this->api_key);
        }

        return $this->request;
    }
}
