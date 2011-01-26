<?php

namespace OAuth\Tests\SignatureMethod;

require_once(__DIR__ . '/../../../common.php');

class RsaSha1Test extends \PHPUnit_Framework_TestCase
{
    private $method;

    public function setUp() {
        $this->method = new \OAuth\Tests\Mock\SignatureMethod\RsaSha1();
    }

    public function testIdentifyAsRsaSha1() {
        $this->assertEquals('RSA-SHA1', $this->method->getName());
    }

    public function testBuildSignature() {
        if (!function_exists('openssl_get_privatekey')) {
            $this->markTestSkipped('OpenSSL not available, can\'t test RSA-SHA1 functionality');
        }

        // Tests taken from http://wiki.oauth.net/TestCases section 9.3 ("RSA-SHA1")
        $request = new \OAuth\Tests\Mock\BaseStringRequest('GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacaction.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3D13917289812797014437%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1196666512%26oauth_version%3D1.0%26size%3Doriginal');
        $consumer = new \OAuth\Consumer('dpf43f3p2l4k3l03', '__unused__');
        $token = NULL;
        $signature = 'jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=';
        $this->assertEquals($signature, $this->method->buildSignature($request, $consumer, $token));
    }

    public function testVerifySignature() {
        if (!function_exists('openssl_get_privatekey')) {
            $this->markTestSkipped('OpenSSL not available, can\'t test RSA-SHA1 functionality');
        }

        // Tests taken from http://wiki.oauth.net/TestCases section 9.3 ("RSA-SHA1")
        $request = new \OAuth\Tests\Mock\BaseStringRequest('GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacaction.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3D13917289812797014437%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1196666512%26oauth_version%3D1.0%26size%3Doriginal');
        $consumer = new \OAuth\Consumer('dpf43f3p2l4k3l03', '__unused__');
        $token = NULL;
        $signature = 'jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=';
        $this->assertTrue($this->method->checkSignature($request, $consumer, $token, $signature));
    }
}
