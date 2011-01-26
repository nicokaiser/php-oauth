<?php
/*
 * Licensed under the MIT license:
 * <http://www.opensource.org/licenses/mit-license.php>
 */

namespace OAuth;

/**
 * A database abstraction used to lookup consumers and tokens
 * 
 * @author Andy Smith <termie@google.com>
 * @author Nico Kaiser <kaiser@boerse-go.de>
 */
abstract class DataStore
{
    /**
     * Look up a Consumer in the datastore and return the Consumer object
     * 
     * @param string $consumerKey
     * @return \OAuth\Consumer
     */
    abstract public function lookupConsumer($consumerKey);

    /**
     * Look up a Token in the datastore and return the Token object
     * 
     * @param \OAuth\Consumer $consumer
     * @param string $tokenType
     * @param string $token
     * @return \OAuth\Token 
     */
    abstract public function lookupToken($consumer, $tokenType, $token);

    /**
     * Look up a nonce in the datastore and return the Token object
     * 
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     * @param string $nonce
     * @param int $timestamp
     */
    abstract public function lookupNonce($consumer, $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this consumer
     * 
     * @param \OAuth\Consumer $consumer
     * @param <type> $callback
     */
    abstract public function newRequestToken($consumer, $callback = null);

    /**
     * Return a new access token attached to this consumer
     * for the user associated with this token if the request token
     * is authorized should also invalidate the request token
     *
     * @param \OAuth\Token $token
     * @param \OAuth\Consumer $consumer
     * @param <type> $verifier 
     */
    abstract public function newAccessToken($token, $consumer, $verifier = null);
}
