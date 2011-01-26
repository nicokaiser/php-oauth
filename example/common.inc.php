<?php

require_once(__DIR__ . '/../lib/SplClassLoader.php');

$classLoader = new SplClassLoader('OAuth', __DIR__ . '/../lib');
$classLoader->register();

require_once(__DIR__ . '/TestOAuthServer.php');

/*
 * Config Section
 */
$domain = $_SERVER['HTTP_HOST'];
$base = "/oauth/example";
$base_url = "http://$domain$base";

/**
 * Some default objects
 */

$test_server = new \TestOAuthServer(new \MockOAuthDataStore());
$hmac_method = new \OAuth\SignatureMethod\HmacSha1();
$plaintext_method = new \OAuth\SignatureMethod\Plaintext();
$rsa_method = new \TestOAuthSignatureMethod_RSA_SHA1();

$test_server->addSignatureMethod($hmac_method);
$test_server->addSignatureMethod($plaintext_method);
$test_server->addSignatureMethod($rsa_method);

$sig_methods = $test_server->getSignatureMethods();
