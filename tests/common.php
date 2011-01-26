<?php

require_once 'PHPUnit/Framework.php';
require_once(__DIR__ . '/../lib/SplClassLoader.php');

$classLoader = new SplClassLoader('OAuth\Tests', __DIR__ . '/../tests');
$classLoader->register();

$classLoader = new SplClassLoader('OAuth', __DIR__ . '/../lib');
$classLoader->register();
