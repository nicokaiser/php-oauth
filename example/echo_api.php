<?php

require_once("common.inc.php");

try {
    $req = \OAuth\Request::fromRequest();
    list($consumer, $token) = $test_server->verifyRequest($req);

    // lsit back the non-OAuth params
    $total = array();
    foreach ($req->getParameters() as $k => $v) {
        if (substr($k, 0, 5) == "oauth")
            continue;
        $total[] = urlencode($k) . "=" . urlencode($v);
    }
    print implode("&", $total);
} catch (\OAuth\Exception $e) {
    print($e->getMessage() . "\n<hr />\n");
    print_r($req);
    die();
}
