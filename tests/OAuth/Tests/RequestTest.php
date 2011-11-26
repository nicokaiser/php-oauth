<?php

namespace OAuth\Tests;

require_once(__DIR__ . '/../../common.php');

/**
 * Tests of \OAuth\Request
 *
 * The tests works by using \OAuth\Tests\TestUtils::buildRequest
 * to populare $_SERVER, $_GET & $_POST.
 *
 * Most of the base string and signature tests
 * are either very simple or based upon
 * http://wiki.oauth.net/TestCases
 */
class RequestTest extends \PHPUnit_Framework_TestCase {

    public function testCanGetSingleParameter() {
        // Yes, a awesomely boring test.. But if this doesn't work, the other tests is unreliable
        $request = new \OAuth\Request('', '', array('test' => 'foo'));
        $this->assertEquals('foo', $request->getParameter('test'), 'Failed to read back parameter');

        $request = new \OAuth\Request('', '', array('test' => array('foo', 'bar')));
        $this->assertEquals(array('foo', 'bar'), $request->getParameter('test'), 'Failed to read back parameter');


        $request = new \OAuth\Request('', '', array('test' => 'foo', 'bar' => 'baz'));
        $this->assertEquals('foo', $request->getParameter('test'), 'Failed to read back parameter');
        $this->assertEquals('baz', $request->getParameter('bar'), 'Failed to read back parameter');
    }

    public function testGetAllParameters() {
        // Yes, a awesomely boring test.. But if this doesn't work, the other tests is unreliable
        $request = new \OAuth\Request('', '', array('test' => 'foo'));
        $this->assertEquals(array('test' => 'foo'), $request->getParameters(), 'Failed to read back parameters');

        $request = new \OAuth\Request('', '', array('test' => 'foo', 'bar' => 'baz'));
        $this->assertEquals(array('test' => 'foo', 'bar' => 'baz'), $request->getParameters(), 'Failed to read back parameters');

        $request = new \OAuth\Request('', '', array('test' => array('foo', 'bar')));
        $this->assertEquals(array('test' => array('foo', 'bar')), $request->getParameters(), 'Failed to read back parameters');
    }

    public function testSetParameters() {
        $request = new \OAuth\Request('', '');
        $this->assertEquals(NULL, $request->getParameter('test'), 'Failed to assert that non-existing parameter is NULL');

        $request->setParameter('test', 'foo');
        $this->assertEquals('foo', $request->getParameter('test'), 'Failed to set single-entry parameter');

        $request->setParameter('test', 'bar');
        $this->assertEquals(array('foo', 'bar'), $request->getParameter('test'), 'Failed to set single-entry parameter');

        $request->setParameter('test', 'bar', false);
        $this->assertEquals('bar', $request->getParameter('test'), 'Failed to set single-entry parameter');
    }

    public function testUnsetParameter() {
        $request = new \OAuth\Request('', '');
        $this->assertEquals(NULL, $request->getParameter('test'));

        $request->setParameter('test', 'foo');
        $this->assertEquals('foo', $request->getParameter('test'));

        $request->unsetParameter('test');
        $this->assertEquals(NULL, $request->getParameter('test'), 'Failed to unset parameter');
    }

    public function testCreateRequestFromConsumerAndToken() {
        $cons = new \OAuth\Consumer('key', 'kd94hf93k423kf44');
        $token = new \OAuth\Token('token', 'pfkkdhi9sl3r4s00');

        $request = \OAuth\Request::fromConsumerAndToken($cons, $token, 'POST', 'http://example.com');
        $this->assertEquals('POST', $request->getNormalizedHttpMethod());
        $this->assertEquals('http://example.com', $request->getNormalizedHttpUrl());
        $this->assertEquals('1.0', $request->getParameter('oauth_version'));
        $this->assertEquals($cons->getKey(), $request->getParameter('oauth_consumer_key'));
        $this->assertEquals($token->getKey(), $request->getParameter('oauth_token'));
        $this->assertEquals(time(), $request->getParameter('oauth_timestamp'));
        $this->assertRegExp('/[0-9a-f]{32}/', $request->getParameter('oauth_nonce'));
        // We don't know what the nonce will be, except it'll be md5 and hence 32 hexa digits

        $request = \OAuth\Request::fromConsumerAndToken($cons, $token, 'POST', 'http://example.com', array('oauth_nonce' => 'foo'));
        $this->assertEquals('foo', $request->getParameter('oauth_nonce'));

        $request = \OAuth\Request::fromConsumerAndToken($cons, NULL, 'POST', 'http://example.com', array('oauth_nonce' => 'foo'));
        $this->assertNull($request->getParameter('oauth_token'));

        // Test that parameters given in the $http_url instead of in the $parameters-parameter
        // will still be picked up
        $request = \OAuth\Request::fromConsumerAndToken($cons, $token, 'POST', 'http://example.com/?foo=bar');
        $this->assertEquals('http://example.com/', $request->getNormalizedHttpUrl());
        $this->assertEquals('bar', $request->getParameter('foo'));
    }

    public function testBuildRequestFromPost() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'foo=bar&baz=blargh');
        $this->assertEquals(array('foo' => 'bar', 'baz' => 'blargh'), \OAuth\Request::fromRequest()->getParameters(), 'Failed to parse POST parameters');
    }

    public function testBuildRequestFromGet() {
        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://testbed/test?foo=bar&baz=blargh');
        $this->assertEquals(array('foo' => 'bar', 'baz' => 'blargh'), \OAuth\Request::fromRequest()->getParameters(), 'Failed to parse GET parameters');
    }

    public function testBuildRequestFromHeader() {
        $test_header = 'OAuth realm="",oauth_foo=bar,oauth_baz="bla,rgh"';
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', '', $test_header);
        $this->assertEquals(array('oauth_foo' => 'bar', 'oauth_baz' => 'bla,rgh'), \OAuth\Request::fromRequest()->getParameters(), 'Failed to split auth-header correctly');
    }

    public function testHasProperParameterPriority() {
        $test_header = 'OAuth realm="",oauth_foo=header';
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test?oauth_foo=get', 'oauth_foo=post', $test_header);
        $this->assertEquals('header', \OAuth\Request::fromRequest()->getParameter('oauth_foo'), 'Loaded parameters in with the wrong priorities');

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test?oauth_foo=get', 'oauth_foo=post');
        $this->assertEquals('post', \OAuth\Request::fromRequest()->getParameter('oauth_foo'), 'Loaded parameters in with the wrong priorities');

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test?oauth_foo=get');
        $this->assertEquals('get', \OAuth\Request::fromRequest()->getParameter('oauth_foo'), 'Loaded parameters in with the wrong priorities');
    }

    public function testNormalizeHttpMethod() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test');
        $this->assertEquals('POST', \OAuth\Request::fromRequest()->getNormalizedHttpMethod(), 'Failed to normalize HTTP method: POST');

        \OAuth\Tests\TestUtils::buildRequest('post', 'http://testbed/test');
        $this->assertEquals('POST', \OAuth\Request::fromRequest()->getNormalizedHttpMethod(), 'Failed to normalize HTTP method: post');

        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://testbed/test');
        $this->assertEquals('GET', \OAuth\Request::fromRequest()->getNormalizedHttpMethod(), 'Failed to normalize HTTP method: GET');

        \OAuth\Tests\TestUtils::buildRequest('PUT', 'http://testbed/test');
        $this->assertEquals('PUT', \OAuth\Request::fromRequest()->getNormalizedHttpMethod(), 'Failed to normalize HTTP method: PUT');
    }

    public function testNormalizeParameters() {
        // This is mostly repeats of OAuthUtilTest::testParseParameters & OAuthUtilTest::TestBuildHttpQuery
        // Tests taken from
        // http://wiki.oauth.net/TestCases ("Normalize Request Parameters")
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'name');
        $this->assertEquals('name=', \OAuth\Request::fromRequest()->getSignableParameters());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'a=b');
        $this->assertEquals('a=b', \OAuth\Request::fromRequest()->getSignableParameters());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'a=b&c=d');
        $this->assertEquals('a=b&c=d', \OAuth\Request::fromRequest()->getSignableParameters());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'a=x%21y&a=x+y');
        $this->assertEquals('a=x%20y&a=x%21y', \OAuth\Request::fromRequest()->getSignableParameters());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'x%21y=a&x=a');
        $this->assertEquals('x=a&x%21y=a', \OAuth\Request::fromRequest()->getSignableParameters());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'a=1&c=hi there&f=25&f=50&f=a&z=p&z=t');
        $this->assertEquals('a=1&c=hi%20there&f=25&f=50&f=a&z=p&z=t', \OAuth\Request::fromRequest()->getSignableParameters());
    }

    public function testNormalizeHttpUrl() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com');
        $this->assertEquals('http://example.com', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'https://example.com');
        $this->assertEquals('https://example.com', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());

        // Tests that http on !80 and https on !443 keeps the port
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com:8080');
        $this->assertEquals('http://example.com:8080', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'https://example.com:80');
        $this->assertEquals('https://example.com:80', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com:443');
        $this->assertEquals('http://example.com:443', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());
        
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://Example.COM');
        $this->assertEquals('http://example.com', \OAuth\Request::fromRequest()->getNormalizedHttpUrl());
    }

    public function testBuildPostData() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com');
        $this->assertEquals('', \OAuth\Request::fromRequest()->toPostdata());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'foo=bar');
        $this->assertEquals('foo=bar', \OAuth\Request::fromRequest()->toPostdata());

        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://example.com?foo=bar');
        $this->assertEquals('foo=bar', \OAuth\Request::fromRequest()->toPostdata());
    }

    public function testBuildUrl() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com');
        $this->assertEquals('http://example.com', \OAuth\Request::fromRequest()->toUrl());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'foo=bar');
        $this->assertEquals('http://example.com?foo=bar', \OAuth\Request::fromRequest()->toUrl());

        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://example.com?foo=bar');
        $this->assertEquals('http://example.com?foo=bar', \OAuth\Request::fromRequest()->toUrl());
    }

    public function testConvertToString() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com');
        $this->assertEquals('http://example.com', (string) \OAuth\Request::fromRequest());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'foo=bar');
        $this->assertEquals('http://example.com?foo=bar', (string) \OAuth\Request::fromRequest());

        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://example.com?foo=bar');
        $this->assertEquals('http://example.com?foo=bar', (string) \OAuth\Request::fromRequest());
    }

    public function testBuildHeader() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com');
        $this->assertEquals('Authorization: OAuth', \OAuth\Request::fromRequest()->toHeader());
        $this->assertEquals('Authorization: OAuth realm="test"', \OAuth\Request::fromRequest()->toHeader('test'));

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'foo=bar');
        $this->assertEquals('Authorization: OAuth', \OAuth\Request::fromRequest()->toHeader());
        $this->assertEquals('Authorization: OAuth realm="test"', \OAuth\Request::fromRequest()->toHeader('test'));

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'oauth_test=foo');
        $this->assertEquals('Authorization: OAuth oauth_test="foo"', \OAuth\Request::fromRequest()->toHeader());
        $this->assertEquals('Authorization: OAuth realm="test",oauth_test="foo"', \OAuth\Request::fromRequest()->toHeader('test'));

        // Is headers supposted to be Urlencoded. More to the point:
        // Should it be baz = bla,rgh or baz = bla%2Crgh ??
        // - morten.fangel
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', '', 'OAuth realm="",oauth_foo=bar,oauth_baz="bla,rgh"');
        $this->assertEquals('Authorization: OAuth oauth_foo="bar",oauth_baz="bla%2Crgh"', \OAuth\Request::fromRequest()->toHeader());
        $this->assertEquals('Authorization: OAuth realm="test",oauth_foo="bar",oauth_baz="bla%2Crgh"', \OAuth\Request::fromRequest()->toHeader('test'));
    }

    public function testWontBuildHeaderWithArrayInput() {
        $this->setExpectedException('\OAuth\Exception');
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://example.com', 'oauth_foo=bar&oauth_foo=baz');
        \OAuth\Request::fromRequest()->toHeader();
    }

    public function testBuildBaseString() {
        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'n=v');
        $this->assertEquals('POST&http%3A%2F%2Ftestbed%2Ftest&n%3Dv', \OAuth\Request::fromRequest()->getSignatureBaseString());

        \OAuth\Tests\TestUtils::buildRequest('POST', 'http://testbed/test', 'n=v&n=v2');
        $this->assertEquals('POST&http%3A%2F%2Ftestbed%2Ftest&n%3Dv%26n%3Dv2', \OAuth\Request::fromRequest()->getSignatureBaseString());

        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://example.com?n=v');
        $this->assertEquals('GET&http%3A%2F%2Fexample.com&n%3Dv', \OAuth\Request::fromRequest()->getSignatureBaseString());

        $params = 'oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1191242090';
        $params .= '&oauth_nonce=hsu94j3884jdopsl&oauth_signature_method=PLAINTEXT&oauth_signature=ignored';
        \OAuth\Tests\TestUtils::buildRequest('POST', 'https://photos.example.net/request_token', $params);
        $this->assertEquals('POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_'
                . 'consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884j'
                . 'dopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestam'
                . 'p%3D1191242090%26oauth_version%3D1.0',
                \OAuth\Request::fromRequest()->getSignatureBaseString());

        $params = 'file=vacation.jpg&size=original&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03';
        $params .= '&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh';
        $params .= '&oauth_signature=ignored&oauth_signature_method=HMAC-SHA1';
        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://photos.example.net/photos?' . $params);
        $this->assertEquals('GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation'
                . '.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%'
                . '3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26o'
                . 'auth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jd'
                . 'k%26oauth_version%3D1.0%26size%3Doriginal',
                \OAuth\Request::fromRequest()->getSignatureBaseString());
    }

    public function testBuildSignature() {
        $params = 'file=vacation.jpg&size=original&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03';
        $params .= '&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh';
        $params .= '&oauth_signature=ignored&oauth_signature_method=HMAC-SHA1';
        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://photos.example.net/photos?' . $params);
        $r = \OAuth\Request::fromRequest();

        $cons = new \OAuth\Consumer('key', 'kd94hf93k423kf44');
        $token = new \OAuth\Token('token', 'pfkkdhi9sl3r4s00');

        $hmac = new \OAuth\SignatureMethod\HmacSha1();
        $plaintext = new \OAuth\SignatureMethod\Plaintext();

        $this->assertEquals('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $r->buildSignature($hmac, $cons, $token));
        $this->assertEquals('kd94hf93k423kf44&pfkkdhi9sl3r4s00', $r->buildSignature($plaintext, $cons, $token));
    }

    public function testSign() {
        $params = 'file=vacation.jpg&size=original&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03';
        $params .= '&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh';
        $params .= '&oauth_signature=__ignored__&oauth_signature_method=HMAC-SHA1';
        \OAuth\Tests\TestUtils::buildRequest('GET', 'http://photos.example.net/photos?' . $params);
        $r = \OAuth\Request::fromRequest();

        $cons = new \OAuth\Consumer('key', 'kd94hf93k423kf44');
        $token = new \OAuth\Token('token', 'pfkkdhi9sl3r4s00');

        $hmac = new \OAuth\SignatureMethod\HmacSha1();
        $plaintext = new \OAuth\SignatureMethod\Plaintext();

        // We need to test both what the parameter is, and how the serialized request is..

        $r->signRequest($hmac, $cons, $token);
        $this->assertEquals('HMAC-SHA1', $r->getParameter('oauth_signature_method'));
        $this->assertEquals('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $r->getParameter('oauth_signature'));
        $expectedPostdata = 'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&'
                . 'oauth_signature=tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D&oauth_signature_method=HMAC-SHA1&'
                . 'oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original';
        $this->assertEquals($expectedPostdata, $r->toPostdata());

        $r->signRequest($plaintext, $cons, $token);
        $this->assertEquals('PLAINTEXT', $r->getParameter('oauth_signature_method'));
        $this->assertEquals('kd94hf93k423kf44&pfkkdhi9sl3r4s00', $r->getParameter('oauth_signature'));
        $expectedPostdata = 'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&'
                . 'oauth_signature=kd94hf93k423kf44%26pfkkdhi9sl3r4s00&oauth_signature_method=PLAINTEXT&'
                . 'oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original';
        $this->assertEquals($expectedPostdata, $r->toPostdata());
    }
}
