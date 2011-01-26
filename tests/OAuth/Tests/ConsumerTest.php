<?php

namespace OAuth\Tests\Mock;

require_once(__DIR__ . '/../../common.php');

class ConsumerTest extends \PHPUnit_Framework_TestCase
{
    public function testConvertToString()
    {
        $consumer = new \OAuth\Consumer('key', 'secret');
        $this->assertEquals('OAuthConsumer[key=key,secret=secret]', (string) $consumer);
    }
}
