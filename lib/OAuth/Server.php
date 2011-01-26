<?php
/*
 * Licensed under the MIT license:
 * <http://www.opensource.org/licenses/mit-license.php>
 */

namespace OAuth;

/**
 * A worker to check a requests validity against a data store
 * 
 * @author Andy Smith <termie@google.com>
 * @author Nico Kaiser <kaiser@boerse-go.de>
 */
class Server
{
    protected $timestampThreshold = 300; // in seconds, five minutes
    protected $version = '1.0';             // hi blaine
    protected $signatureMethods = array();
    protected $dataStore;

    /**
     * Constructor
     * 
     * @param \OAuth\DataStore $dataStore
     */
    public function __construct($dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Add a signature method
     * 
     * @param \OAuth\SignatureMethod\SignatureMethod $signatureMethod
     */
    public function addSignatureMethod($signatureMethod)
    {
        $this->signatureMethods[$signatureMethod->getName()] =
            $signatureMethod;
    }

    // high level functions

    /**
     * Process a request_token request
     * returns the request token on success
     *
     * @param \OAuth\Request $request
     * @return \OAuth\Token
     */
    public function fetchRequestToken($request)
    {
        $this->getVersion($request);

        $consumer = $this->getConsumer($request);

        // no token required for the initial token request
        $token = null;

        $this->checkSignature($request, $consumer, $token);

        // Rev A change
        $callback = $request->getParameter('oauth_callback');
        $newToken = $this->dataStore->newRequestToken($consumer, $callback);

        return $newToken;
    }
    
    /**
     * Process an access_token request
     * returns the access token on success
     *
     * @param \OAuth\Request $request
     * @return \OAuth\Token
     */
    public function fetchAccessToken($request)
    {
        $this->getVersion($request);

        $consumer = $this->getConsumer($request);

        // requires authorized request token
        $token = $this->getToken($request, $consumer, "request");

        $this->checkSignature($request, $consumer, $token);

        // Rev A change
        $verifier = $request->getParameter('oauth_verifier');
        $newToken = $this->dataStore->newAccessToken($token, $consumer, $verifier);

        return $newToken;
    }

    /**
     * Verify an api call, checks all the parameters
     *
     * @param \OAuth\Request $request
     * @return array (Consumer, Token)
     */
    public function verifyRequest($request)
    {
        $this->getVersion($request);
        $consumer = $this->getConsumer($request);
        $token = $this->getToken($request, $consumer, "access");
        $this->checkSignature($request, $consumer, $token);
        return array($consumer, $token);
    }

    // Internals from here

    /**
     * Get the request version
     *
     * @param \OAuth\Request $request
     * @return string
     * @throws \OAuth\Exception if the version is not supported
     */
    private function getVersion($request)
    {
        $version = $request->getParameter("oauth_version");
        if (!$version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new Exception("OAuth version '$version' not supported");
        }
        return $version;
    }

    /**
     * Figure out the signature with some defaults
     *
     * @param \OAuth\Request $request
     * @return \OAuth\SignatureMethod\SignatureMethod
     * @throws \OAuth\Exception if the method is not supported
     */
    private function getSignatureMethod($request)
    {
        $signatureMethod = $request instanceof Request ? $request->getParameter("oauth_signature_method") : null;

        if (!$signatureMethod) {
            // According to chapter 7 ("Accessing Protected Ressources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new Exception('No signature method parameter. This parameter is required');
        }

        if (!in_array($signatureMethod, array_keys($this->signatureMethods))) {
            throw new Exception(
                "Signature method '$signatureMethod' not supported " .
                "try one of the following: " .
                implode(", ", array_keys($this->signatureMethods))
            );
        }
        return $this->signatureMethods[$signatureMethod];
    }

    /**
     * Try to find the consumer for the provided request's consumer key
     * 
     * @param \OAuth\Request $request
     * @return \OAuth\Consumer
     * @throws \OAuth\Exception
     */
    private function getConsumer($request)
    {
        $consumerKey = $request instanceof Request ? $request->getParameter("oauth_consumer_key") : null;

        if (!$consumerKey) {
            throw new Exception('Invalid consumer key');
        }

        $consumer = $this->dataStore->lookupConsumer($consumerKey);
        if (!$consumer) {
            throw new Exception('Invalid consumer');
        }

        return $consumer;
    }

    /**
     * Try to find the token for the provided request's token key
     *
     * @param \OAuth\Request $request
     * @param \OAuth\Consumer $consumer
     * @param string $tokenType
     * @return \OAuth\Token
     * @throws \OAuth\Exception
     */
    private function getToken($request, $consumer, $tokenType = 'access')
    {
        $tokenField = $request instanceof Request ? $request->getParameter('oauth_token') : null;

        $token = $this->dataStore->lookupToken($consumer, $tokenType, $tokenField);
        if (!$token) {
            throw new Exception("Invalid $tokenType token: $tokenField");
        }
        return $token;
    }

    /**
     * All-in-one function to check the signature on a request
     * should guess the signature method appropriately
     *
     * @param \OAuth\Request $request
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     * @throws \OAuth\Exception
     */
    private function checkSignature($request, $consumer, $token)
    {
        // this should probably be in a different method
        $timestamp = $request instanceof Request ? $request->getParameter('oauth_timestamp') : null;
        $nonce = $request instanceof Request ? $request->getParameter('oauth_nonce') : null;

        $this->checkTimestamp($timestamp);
        $this->checkNonce($consumer, $token, $nonce, $timestamp);

        $signatureMethod = $this->getSignatureMethod($request);

        $signature = $request->getParameter('oauth_signature');
        $validSig = $signatureMethod->checkSignature(
            $request,
            $consumer,
            $token,
            $signature
        );

        if (!$validSig) {
            throw new Exception('Invalid signature');
        }
    }

    /**
     * Check that the timestamp is new enough
     *
     * @param int $timestamp
     * @throws \OAuth\Exception
     */
    private function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new Exception(
                'Missing timestamp parameter. The parameter is required'
            );
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestampThreshold) {
            throw new Exception(
                "Expired timestamp, yours $timestamp, ours $now"
            );
        }
    }

    /**
     * Check that the nonce is not repeated
     *
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     * @param string $nonce
     * @param int $timestamp
     * @throws \OAuth\Exception
     */
    private function checkNonce($consumer, $token, $nonce, $timestamp)
    {
        if (!$nonce) {
            throw new Exception(
                'Missing nonce parameter. The parameter is required'
            );
        }

        // verify that the nonce is uniqueish
        $found = $this->dataStore->lookupNonce(
            $consumer,
            $token,
            $nonce,
            $timestamp
        );
        if ($found) {
            throw new Exception("Nonce already used: $nonce");
        }
    }
}
