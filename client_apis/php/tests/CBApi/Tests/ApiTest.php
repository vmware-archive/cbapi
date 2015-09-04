<?php

namespace CBApi\Tests;

use CBApi\Connection\Request;
use CBApi\Rest\GetRest;
use CBApi\Rest\PutRest;
use CBApi\Exception\ConnectionErrorException;

/**
 * Class ApiTest
 *
 * @package CBApi\Tests
 */
class ApiTest extends \PHPUnit_Framework_TestCase
{
    /** @var \CBApi\Rest\GetRest */
    private $getRest;

    /** @var \CBApi\Rest\PutRest */
    private $putRest;

    /** @var \CBApi\Connection\Request */
    private $request;

    /** @var array */
    private static $generalData = [
        'url'         => 'http://localhosterino',
        'ssl_url'     => 'https://localhosterino',
        'api_key'     => '12345-12345-12354-12345',
        'api_key_int' => 12345123451234512345,
        'license'     => '1234512345123456'
    ];

    /**
     * @return array
     */
    public static function connectionProvider()
    {
        return [
            [self::$generalData['url'], self::$generalData['api_key']],
            [self::$generalData['ssl_url'], self::$generalData['api_key_int']],
            [self::$generalData['url'], self::$generalData['api_key_int']],
            [self::$generalData['ssl_url'], self::$generalData['api_key']]
        ];
    }

    public function setUp()
    {
        $this->request = new Request(self::$generalData['url'], self::$generalData['api_key']);
    }

    /**
     * @dataProvider connectionProvider
     * @param $api_key
     * @param $url
     */
    public function testRequestObj($url, $api_key)
    {
        self::assertNotNull($this->createRequestObj($url, $api_key));
    }

    /**
     * @depends testRequestObj
     */
    public function testGetNotNull()
    {
        self::assertNotNull($this->getGetObj());
    }

    /**
     * @depends testRequestObj
     */
    public function testPutNotNull()
    {
        self::assertNotNull($this->getPutObj());
    }

    /**
     * @depends testGetNotNull
     */
    public function testBadGetConnection()
    {
        self::setExpectedException(ConnectionErrorException::class);
        self::assertEquals(false, $this->getGetObj()->info());
    }

    /**
     * @depends testPutNotNull
     */
    public function testBadPutConnection()
    {
        self::setExpectedException(ConnectionErrorException::class);
        self::assertEquals(false, $this->getPutObj()->license(self::$generalData['license']));
    }

    /**
     * @return \CBApi\Rest\GetRest
     */
    private function getGetObj()
    {
        if (!$this->getRest) {
            $this->getRest = new GetRest($this->request);
        }

        return $this->getRest;
    }

    /**
     * @return \CBApi\Rest\PutRest
     */
    private function getPutObj()
    {
        if (!$this->putRest) {
            $this->putRest = new PutRest($this->request);
        }

        return $this->putRest;
    }

    /**
     * @param $url
     * @param $api_key
     * @return \CBApi\Connection\Request
     */
    private function createRequestObj($url, $api_key)
    {
        return new Request($url, $api_key);
    }
}
