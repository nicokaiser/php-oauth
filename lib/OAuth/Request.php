<?php
/*
 * Licensed under the MIT license:
 * <http://www.opensource.org/licenses/mit-license.php>
 */

namespace OAuth;

/**
 * Represents the request
 * 
 * @author Andy Smith <termie@google.com>
 * @author Nico Kaiser <kaiser@boerse-go.de>
 */
class Request
{
    protected $parameters;
    protected $httpMethod;
    protected $httpUrl;
    
    protected $baseString;

    public static $version = '1.0';
    public static $POST_INPUT = 'php://input';

    /**
     * Constructor
     * 
     * @param string $httpMethod
     * @param string $httpUrl
     * @param array $parameters OPTIONAL
     */
    public function __construct($httpMethod, $httpUrl, $parameters = null)
    {
        $parameters = ($parameters) ? $parameters : array();
        $parameters = array_merge(Util::parseParameters(parse_url($httpUrl, PHP_URL_QUERY)), $parameters);
        $this->parameters = $parameters;
        $this->httpMethod = $httpMethod;
        $this->httpUrl = $httpUrl;
    }

    /**
     * Attempt to build up a request from what was passed to the server
     *
     * @param string $httpMethod OPTIONAL
     * @param string $httpUrl OPTIONAL
     * @param array $parameters OPTIONAL
     * @return \OAuth\Request
     */
    public static function fromRequest($httpMethod = null, $httpUrl = null, $parameters = null)
    {
        $scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != "on") ? 'http' : 'https';
        $httpUrl = ($httpUrl) ? $httpUrl : $scheme .
            '://' . $_SERVER['SERVER_NAME'] .
            ':' .
            $_SERVER['SERVER_PORT'] .
            $_SERVER['REQUEST_URI'];
        $httpMethod = ($httpMethod) ? $httpMethod : $_SERVER['REQUEST_METHOD'];

        // We weren't handed any parameters, so let's find the ones relevant to
        // this request.
        // If you run XML-RPC or similar you should use this to provide your own
        // parsed parameter-list
        if (!$parameters) {
            // Find request headers
            $requestHeaders = Util::getHeaders();

            // Parse the query-string to find GET parameters
            $parameters = Util::parseParameters($_SERVER['QUERY_STRING']);

            // It's a POST request of the proper content-type, so parse POST
            // parameters and add those overriding any duplicates from GET
            if ($httpMethod == "POST"
                && isset($requestHeaders['Content-Type'])
                && strstr($requestHeaders['Content-Type'], 'application/x-www-form-urlencoded')) {
                $postData = Util::parseParameters(file_get_contents(self::$POST_INPUT));
                $parameters = array_merge($parameters, $postData);
            }

            // We have a Authorization-header with OAuth data. Parse the header
            // and add those overriding any duplicates from GET or POST
            if (isset($requestHeaders['Authorization']) &&
                substr($requestHeaders['Authorization'], 0, 6) == 'OAuth ') {
                $headerParameters = Util::splitHeader(
                    $requestHeaders['Authorization']
                );
                $parameters = array_merge($parameters, $headerParameters);
            }
        }

        return new Request($httpMethod, $httpUrl, $parameters);
    }
    
    /**
     * Pretty much a helper function to set up the request
     *
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     * @param string $httpMethod
     * @param string $httpUrl
     * @param array $parameters OPTIONAL
     * @return \OAuth\Request
     */
    public static function fromConsumerAndToken($consumer, $token, $httpMethod, $httpUrl, $parameters = null)
    {
        $parameters = ($parameters) ? $parameters : array();
        $defaults = array("oauth_version" => Request::$version,
            "oauth_nonce" => Request::generateNonce(),
            "oauth_timestamp" => Request::generateTimestamp(),
            "oauth_consumer_key" => $consumer->getKey());
        if ($token)
            $defaults['oauth_token'] = $token->getKey();

        $parameters = array_merge($defaults, $parameters);

        return new Request($httpMethod, $httpUrl, $parameters);
    }

    /**
     * Set parameter value
     * 
     * @param string $name
     * @param string $value
     * @param bool $allowDuplicates
     */
    public function setParameter($name, $value, $allowDuplicates = true)
    {
        if ($allowDuplicates && isset($this->parameters[$name])) {
            // We have already added parameter(s) with this name, so add to the list
            if (is_scalar($this->parameters[$name])) {
                // This is the first duplicate, so transform scalar (string)
                // into an array so we can add the duplicates
                $this->parameters[$name] = array($this->parameters[$name]);
            }

            $this->parameters[$name][] = $value;
        } else {
            $this->parameters[$name] = $value;
        }
    }

    /**
     * Get a parameter value
     *
     * @param string $name
     * @return string
     */
    public function getParameter($name)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
    }

    /**
     * Get all parameters
     * 
     * @return array
     */
    public function getParameters()
    {
        return $this->parameters;
    }

    /**
     * Unset a parameter
     * 
     * @param string $name
     */
    public function unsetParameter($name)
    {
        unset($this->parameters[$name]);
    }

    /**
     * The request parameters, sorted and concatenated into a normalized string.
     *
     * @return string
     */
    public function getSignableParameters()
    {
        // Grab all parameters
        $params = $this->parameters;

        // Remove oauth_signature if present
        // Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
        if (isset($params['oauth_signature'])) {
            unset($params['oauth_signature']);
        }

        return Util::buildHttpQuery($params);
    }

    /**
     * Returns the base string of this request
     *
     * The base string defined as the method, the url
     * and the parameters (normalized), each urlencoded
     * and the concated with &.
     *
     * @return string
     */
    public function getSignatureBaseString()
    {
        $parts = array(
            $this->getNormalizedHttpMethod(),
            $this->getNormalizedHttpUrl(),
            $this->getSignableParameters()
        );

        $parts = Util::urlencodeRfc3986($parts);

        return implode('&', $parts);
    }

    /**
     * Just uppercases the http method
     *
     * @return string
     */
    public function getNormalizedHttpMethod()
    {
        return strtoupper($this->httpMethod);
    }

    /**
     * Parses the url and rebuilds it to be
     * scheme://host/path
     *
     * @return string
     */
    public function getNormalizedHttpUrl()
    {
        $parts = parse_url($this->httpUrl);

        $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
        $port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
        $host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
        $path = (isset($parts['path'])) ? $parts['path'] : '';

        if (($scheme == 'https' && $port != '443')
                || ($scheme == 'http' && $port != '80')) {
            $host = "$host:$port";
        }
        return "$scheme://$host$path";
    }

    /**
     * Builds a url usable for a GET request
     *
     * @return string
     */
    public function toUrl()
    {
        $postData = $this->toPostdata();
        $out = $this->getNormalizedHttpUrl();
        if ($postData) {
            $out .= '?' . $postData;
        }
        return $out;
    }

    /**
     * Builds the data one would send in a POST request
     *
     * @return string
     */
    public function toPostdata()
    {
        return Util::buildHttpQuery($this->parameters);
    }

    /**
     * Builds the Authorization: header
     *
     * @return string
     */
    public function toHeader($realm = null)
    {
        $first = true;
        if ($realm) {
            $out = 'Authorization: OAuth realm="' . Util::urlencodeRfc3986($realm) . '"';
            $first = false;
        } else
            $out = 'Authorization: OAuth';

        $total = array();
        foreach ($this->parameters as $k => $v) {
            if (substr($k, 0, 5) != "oauth")
                continue;
            if (is_array($v)) {
                throw new Exception('Arrays not supported in headers');
            }
            $out .= ($first) ? ' ' : ',';
            $out .= Util::urlencodeRfc3986($k) . '="' .
                    Util::urlencodeRfc3986($v) . '"';
            $first = false;
        }
        return $out;
    }

    /**
     * String representation
     * 
     * @return string
     */
    public function __toString()
    {
        return $this->toUrl();
    }

    /**
     * Sign the current request
     * 
     * @param \OAuth\SignatureMethod\SignatureMethod $signatureMethod
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     */
    public function signRequest($signatureMethod, $consumer, $token)
    {
        $this->setParameter(
            "oauth_signature_method",
            $signatureMethod->getName(),
            false
        );
        $signature = $this->buildSignature($signatureMethod, $consumer, $token);
        $this->setParameter("oauth_signature", $signature, false);
    }

    /**
     * Build the signature for signing
     *
     * @param \OAuth\SignatureMethod\SignatureMethod $signatureMethod
     * @param \OAuth\Consumer $consumer
     * @param \OAuth\Token $token
     */
    public function buildSignature($signatureMethod, $consumer, $token)
    {
        $signature = $signatureMethod->buildSignature($this, $consumer, $token);
        return $signature;
    }

    /**
     * Get baseString
     * 
     * @return string
     */
    public function getBaseString()
    {
        return $this->baseString;
    }

    /**
     * Set baseString
     * 
     * @param string $baseString
     */
    public function setBaseString($baseString)
    {
        $this->baseString = $baseString;
    }

    /**
     * Util function: current timestamp
     * 
     * @return int
     */
    private static function generateTimestamp()
    {
        return time();
    }

    /**
     * Util function: current nonce
     * 
     * @return string
     */
    private static function generateNonce()
    {
        $mt = microtime();
        $rand = mt_rand();

        return md5($mt . $rand); // md5s look nicer than numbers
    }
}
