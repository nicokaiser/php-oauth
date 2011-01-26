<?php
/*
 * Licensed under the MIT license:
 * <http://www.opensource.org/licenses/mit-license.php>
 */

namespace OAuth;

/**
 * A data type that represents the identity of the Consumer
 * via its shared secret with the Service Provider.
 * 
 * @author Andy Smith <termie@google.com>
 * @author Nico Kaiser <kaiser@boerse-go.de>
 */
class Consumer
{
    /**
     * @var string
     */
    protected $key;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    private $callbackUrl;

    /**
     * Constructor
     *
     * @param string $key
     * @param string $secret
     * @param string $callbackUrl
     */
    public function __construct($key, $secret, $callbackUrl = null)
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->callbackUrl = $callbackUrl;
    }

    /**
     * Get key
     * 
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Set key
     *
     * @param string $key
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Set secret
     * 
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set secret
     *
     * @param string $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }
    
    /**
     * String representation
     * 
     * @return string
     */
    public function __toString()
    {
        return "OAuthConsumer[key=$this->key,secret=$this->secret]";
    }
}
