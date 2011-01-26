<?php

/**
 * A very naive dbm-based OAuth storage
 *
 * NOTE:
 * This is for reference ONLY, and contains, amongst others, a hole
 * where you can get the token secret easily..
 */
class SimpleOAuthDataStore extends \OAuth\DataStore {

    private $dbh;

    function __construct($path = "oauth.gdbm")
    {
        $this->dbh = dba_popen($path, 'c', 'gdbm');
    }

    function __destruct()
    {
        dba_close($this->dbh);
    }

    function lookupConsumer($consumerKey)
    {
        $rv = dba_fetch("consumer_$consumerKey", $this->dbh);
        if ($rv === false) {
            return null;
        }
        $obj = unserialize($rv);
        if (!($obj instanceof \OAuth\Consumer)) {
            return null;
        }
        return $obj;
    }
    
    function lookupToken($consumer, $tokenType, $token)
    {
        $rv = dba_fetch("${tokenType}_${token}", $this->dbh);
        if ($rv === false) {
            return null;
        }
        $obj = unserialize($rv);
        if (!($obj instanceof \OAuth\Token)) {
            return null;
        }
        return $obj;
    }

    function lookupNonce($consumer, $token, $nonce, $timestamp) {
        if (dba_exists("nonce_$nonce", $this->dbh)) {
            return true;
        } else {
            dba_insert("nonce_$nonce", "1", $this->dbh);
            return false;
        }
    }
    
    function newToken($consumer, $type = "request")
    {
        $key = md5(time());
        $secret = time() + time();
        $token = new \OAuth\Token($key, md5(md5($secret)));
        if (!dba_insert("${type}_$key", serialize($token), $this->dbh)) {
            throw new \OAuth\Exception("doooom!");
        }
        return $token;
    }

    public function newRequestToken($consumer)
    {
        return $this->newToken($consumer, "request");
    }
    
    public function newAccessToken($token, $consumer)
    {
        $token = $this->newToken($consumer, 'access');
        dba_delete("request_" . $token->getKey(), $this->dbh);
        return $token;
    }
}
