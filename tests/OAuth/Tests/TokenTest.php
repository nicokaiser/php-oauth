<?php

namespace OAuth\Tests;

require_once(__DIR__ . '/../../common.php');

class TokenTest extends \PHPUnit_Framework_TestCase {

    public function testSerialize()
    {
        $token = new \OAuth\Token('token', 'secret');
        $this->assertEquals('oauth_token=token&oauth_token_secret=secret', $token->toString());

        $token = new \OAuth\Token('token&', 'secret%');
        $this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', $token->toString());
    }

    public function testConvertToString()
    {
        $token = new \OAuth\Token('token', 'secret');
        $this->assertEquals('oauth_token=token&oauth_token_secret=secret', (string) $token);

        $token = new \OAuth\Token('token&', 'secret%');
        $this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', (string) $token);
    }
}
