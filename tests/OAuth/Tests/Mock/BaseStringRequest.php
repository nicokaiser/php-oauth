<?php

namespace OAuth\Tests\Mock;

/**
 * A very simple class that you can pass a base-string, and then have it returned again.
 * Used for testing the signature-methods
 */
class BaseStringRequest
{
    private $providedBaseString;
    private $baseString;

    public function __construct($bs)
    {
        $this->providedBaseString = $bs;
    }

    public function getSignatureBaseString()
    {
        return $this->providedBaseString;
    }

    public function getBaseString()
    {
        return $this->baseString;
    }
    
    public function setBaseString($baseString)
    {
        $this->baseString = $baseString;
    }
}
