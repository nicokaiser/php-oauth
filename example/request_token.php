<?php

require_once("common.inc.php");

try {
    $req = \OAuth\Request::fromRequest();
    $token = $test_server->fetchRequestToken($req);
    print $token;
} catch (\OAuth\Exception $e) {
    print($e->getMessage() . "\n<hr />\n");
    print_r($req);
    die();
}
