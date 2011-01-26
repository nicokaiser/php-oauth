<?php

namespace OAuth\Tests;

require_once(__DIR__ . '/../../common.php');

/**
 * Tests of OAuthUtil
 */
class ServerTest extends \PHPUnit_Framework_TestCase
{
    private $consumer;
    private $request_token;
    private $access_token;
    private $hmac_sha1;
    private $plaintext;
    private $server;

    public function setUp()
    {
        $this->consumer = new \OAuth\Consumer('key', 'secret');
        $this->request_token = new \OAuth\Token('requestkey', 'requestsecret');
        $this->access_token = new \OAuth\Token('accesskey', 'accesssecret');

        $this->hmac_sha1 = new \OAuth\SignatureMethod\HmacSha1();
        $this->plaintext = new \OAuth\SignatureMethod\Plaintext();

        $this->server = new \OAuth\Server(new \OAuth\Tests\Mock\DataStore());
        $this->server->addSignatureMethod($this->hmac_sha1);
        $this->server->addSignatureMethod($this->plaintext);
    }

    public function testAcceptValidRequest()
    {
        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);
        list($consumer, $token) = $this->server->verifyRequest($request);
        $this->assertEquals($this->consumer, $consumer);
        $this->assertEquals($this->access_token, $token);

        $request->signRequest($this->hmac_sha1, $this->consumer, $this->access_token);
        list($consumer, $token) = $this->server->verifyRequest($request);
        $this->assertEquals($this->consumer, $consumer);
        $this->assertEquals($this->access_token, $token);
    }

    public function testAcceptRequestWithoutVersion()
    {
        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->unsetParameter('oauth_version');
        $request->signRequest($this->hmac_sha1, $this->consumer, $this->access_token);

        $this->server->verifyRequest($request);
    }

    public function testRejectRequestSignedWithRequestToken()
    {
        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->request_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->request_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectRequestWithMissingParameters()
    {
        // The list of required parameters is taken from
        // Chapter 7 ("Accessing Protected Resources")

        $required_parameters = array(
            'oauth_consumer_key',
            'oauth_token',
            'oauth_signature_method',
            'oauth_signature',
            'oauth_timestamp',
            'oauth_nonce'
        );

        foreach ($required_parameters AS $required) {
            $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
            $request->signRequest($this->plaintext, $this->consumer, $this->access_token);
            try {
                $request->unsetParameter($required);
                $this->server->verifyRequest($request);
                $this->fail('Allowed a request without `' . $required . '`');
            } catch (\OAuth\Exception $e) { /* expected */
            }
        }
    }

    public function testRejectPastTimestamp()
    {
        // We change the timestamp to be 10 hours ago, it should throw an exception

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->setParameter('oauth_timestamp', $request->getParameter('oauth_timestamp') - 10 * 60 * 60, false);
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectFutureTimestamp()
    {
        // We change the timestamp to be 10 hours in the future, it should throw an exception

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->setParameter('oauth_timestamp', $request->getParameter('oauth_timestamp') + 10 * 60 * 60, false);
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectUsedNonce()
    {
        // We give a known nonce and should see an exception

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        // The Mock datastore is set to say that the `nonce` nonce is known
        $request->setParameter('oauth_nonce', 'nonce', false);
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectInvalidSignature()
    {
        // We change the signature post-signing to be something invalid

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);
        $request->setParameter('oauth_signature', '__whatever__', false);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectInvalidConsumer()
    {
        // We use the consumer-key "unknown", which isn't known by the datastore.

        $unknown_consumer = new \OAuth\Consumer('unknown', '__unused__');

        $request = \OAuth\Request::fromConsumerAndToken($unknown_consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $unknown_consumer, $this->access_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectInvalidToken()
    {
        // We use the access-token "unknown" which isn't known by the datastore

        $unknown_token = new \OAuth\Token('unknown', '__unused__');

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $unknown_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $unknown_token);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testRejectUnknownSignatureMethod()
    {
        // We use a server that only supports HMAC-SHA1, but requests with PLAINTEXT signature

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);

        $server = new \OAuth\Server(new \OAuth\Tests\Mock\DataStore());
        $server->addSignatureMethod($this->hmac_sha1);

        $this->setExpectedException('\OAuth\Exception');
        $server->verifyRequest($request);
    }

    public function testRejectUnknownVersion()
    {
        // We use the version "1.0a" which isn't "1.0", so reject the request

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);
        $request->setParameter('oauth_version', '1.0a', false);

        $this->setExpectedException('\OAuth\Exception');
        $this->server->verifyRequest($request);
    }

    public function testCreateRequestToken()
    {
        // We request a new Request Token

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, NULL, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, NULL);

        $token = $this->server->fetchRequestToken($request);
        $this->assertEquals($this->request_token, $token);
    }

    public function testRejectSignedRequestTokenRequest()
    {
        // We request a new Request Token, but the request is signed with a token which should fail

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->request_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->request_token);

        $this->setExpectedException('\OAuth\Exception');
        $token = $this->server->fetchRequestToken($request);
    }

    public function testCreateAccessToken()
    {
        // We request a new Access Token

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->request_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->request_token);

        $token = $this->server->fetchAccessToken($request);
        $this->assertEquals($this->access_token, $token);
    }

    public function testRejectUnsignedAccessTokenRequest()
    {
        // We request a new Access Token, but we didn't sign the request with a Access Token

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, NULL, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, NULL);

        $this->setExpectedException('\OAuth\Exception');
        $token = $this->server->fetchAccessToken($request);
    }

    public function testRejectAccessTokenSignedAccessTokenRequest()
    {
        // We request a new Access Token, but the request is signed with an access token, so fail!

        $request = \OAuth\Request::fromConsumerAndToken($this->consumer, $this->access_token, 'POST', 'http://example.com');
        $request->signRequest($this->plaintext, $this->consumer, $this->access_token);

        $this->setExpectedException('\OAuth\Exception');
        $token = $this->server->fetchAccessToken($request);
    }
}
