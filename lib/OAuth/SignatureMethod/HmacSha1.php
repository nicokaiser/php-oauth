<?php
/*
 * Licensed under the MIT license:
 * <http://www.opensource.org/licenses/mit-license.php>
 */

namespace OAuth\SignatureMethod;

use OAuth\Util;

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 *
 * @author Andy Smith <termie@google.com>
 * @author Nico Kaiser <kaiser@boerse-go.de>
 */
class HmacSha1 extends SignatureMethod
{
    function getName()
    {
        return "HMAC-SHA1";
    }

    public function buildSignature($request, $consumer, $token)
    {
        $baseString = $request->getSignatureBaseString();
        $request->setBaseString($baseString);

        $key_parts = array(
            $consumer->getSecret(),
            ($token) ? $token->getSecret() : ""
        );

        $key_parts = Util::urlencodeRfc3986($key_parts);
        $key = implode('&', $key_parts);

        return base64_encode(hash_hmac('sha1', $baseString, $key, true));
    }
}
