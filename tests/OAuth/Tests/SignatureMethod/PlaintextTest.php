<?php

namespace OAuth\Tests\SignatureMethod;

require_once(__DIR__ . '/../../../common.php');

class PlaintextTest extends \PHPUnit_Framework_TestCase {

    private $method;

    public function setUp() {
        $this->method = new \OAuth\SignatureMethod\Plaintext();
    }

    public function testIdentifyAsPlaintext() {
        $this->assertEquals('PLAINTEXT', $this->method->getName());
    }

    public function testBuildSignature() {
        // Tests based on from http://wiki.oauth.net/TestCases section 9.2 ("HMAC-SHA1")
        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'cs');
        $token = null;
        $this->assertEquals('cs&', $this->method->buildSignature($request, $consumer, $token));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'cs');
        $token = new \OAuth\Token('__unused__', 'ts');
        $this->assertEquals('cs&ts', $this->method->buildSignature($request, $consumer, $token));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'kd94hf93k423kf44');
        $token = new \OAuth\Token('__unused__', 'pfkkdhi9sl3r4s00');
        $this->assertEquals('kd94hf93k423kf44&pfkkdhi9sl3r4s00', $this->method->buildSignature($request, $consumer, $token));

        // Tests taken from Chapter 9.4.1 ("Generating Signature") from the spec
        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'djr9rjt0jd78jf88');
        $token = new \OAuth\Token('__unused__', 'jjd999tj88uiths3');
        $this->assertEquals('djr9rjt0jd78jf88&jjd999tj88uiths3', $this->method->buildSignature($request, $consumer, $token));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'djr9rjt0jd78jf88');
        $token = new \OAuth\Token('__unused__', 'jjd99$tj88uiths3');
        $this->assertEquals('djr9rjt0jd78jf88&jjd99%24tj88uiths3', $this->method->buildSignature($request, $consumer, $token));
    }

    public function testVerifySignature() {
        // Tests based on from http://wiki.oauth.net/TestCases section 9.2 ("HMAC-SHA1")
        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'cs');
        $token = null;
        $signature = 'cs&';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'cs');
        $token = new \OAuth\Token('__unused__', 'ts');
        $signature = 'cs&ts';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'kd94hf93k423kf44');
        $token = new \OAuth\Token('__unused__', 'pfkkdhi9sl3r4s00');
        $signature = 'kd94hf93k423kf44&pfkkdhi9sl3r4s00';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));

        // Tests taken from Chapter 9.4.1 ("Generating Signature") from the spec
        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'djr9rjt0jd78jf88');
        $token = new \OAuth\Token('__unused__', 'jjd999tj88uiths3');
        $signature = 'djr9rjt0jd78jf88&jjd999tj88uiths3';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));

        $request = new \OAuth\Tests\Mock\BaseStringRequest('__unused__');
        $consumer = new \OAuth\Consumer('__unused__', 'djr9rjt0jd78jf88');
        $token = new \OAuth\Token('__unused__', 'jjd99$tj88uiths3');
        $signature = 'djr9rjt0jd78jf88&jjd99%24tj88uiths3';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));
    }

}