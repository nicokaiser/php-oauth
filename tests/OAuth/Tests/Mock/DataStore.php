<?php

namespace OAuth\Tests\Mock;

/**
 * A mock store for testing
 */
class DataStore extends \OAuth\DataStore
{
    private $consumer;
    private $requestToken;
    private $accessToken;
    private $nonce;

    function __construct()
    {
        $this->consumer = new \OAuth\Consumer("key", "secret", NULL);
        $this->requestToken = new \OAuth\Token("requestkey", "requestsecret", 1);
        $this->accessToken = new \OAuth\Token("accesskey", "accesssecret", 1);
        $this->nonce = "nonce";
    }

    function lookupConsumer($consumerKey)
    {
        if ($consumerKey == $this->consumer->getKey())
            return $this->consumer;
        return null;
    }

    function lookupToken($consumer, $tokenType, $token)
    {
        $tokenAttrib = $tokenType . "Token";
        if ($consumer->getKey() == $this->consumer->getKey()
                && $token == $this->$tokenAttrib->getKey()) {
            return $this->$tokenAttrib;
        }
        return null;
    }

    function lookupNonce($consumer, $token, $nonce, $timestamp)
    {
        if ($consumer->getKey() == $this->consumer->getKey()
                && (($token && $token->getKey() == $this->requestToken->getKey())
                || ($token && $token->getKey() == $this->accessToken->getKey()))
                && $nonce == $this->nonce) {
            return $this->nonce;
        }
        return null;
    }

    function newRequestToken($consumer, $callback = null)
    {
        if ($consumer->getKey() == $this->consumer->getKey()) {
            return $this->requestToken;
        }
        return null;
    }

    function newAccessToken($token, $consumer, $verifier = null)
    {
        if ($consumer->getKey() == $this->consumer->getKey()
                && $token->getKey() == $this->requestToken->getKey()) {
            return $this->accessToken;
        }
        return null;
    }
}
