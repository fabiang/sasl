<?php

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014 Fabian Grutschus
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * o Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * o Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.|
 * o The names of the authors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Richard Heyes <richard@php.net>
 */

namespace Fabiang\Sasl\Authentication;

use Fabiang\Sasl\Exception\InvalidArgumentException;
use Fabiang\Sasl\Exception\RuntimeException;

/**
 * Implmentation of DIGEST-MD5 SASL mechanism
 *
 * @author Richard Heyes <richard@php.net>
 */
class DigestMD5 extends AbstractAuthentication implements ChallengeAuthenticationInterface
{

    /**
     * Provides the (main) client response for DIGEST-MD5
     * requires a few extra parameters than the other
     * mechanisms, which are unavoidable.
     *
     * @param  string $challenge The digest challenge sent by the server
     * @return string            The digest response (NOT base64 encoded)
     */
    public function createResponse($challenge = null)
    {
        $parsedChallenge = $this->parseChallenge($challenge);
        $authzidString = '';

        $authcid  = $this->options->getAuthcid();
        $pass     = $this->options->getSecret();
        $authzid  = $this->options->getAuthzid();
        $service  = $this->options->getService();
        $hostname = $this->options->getHostname();

        if (!empty($authzid)) {
            $authzidString = 'authzid="' . $authzid . '",';
        }

        if (empty($parsedChallenge)) {
            throw new InvalidArgumentException('Invalid digest challenge');    
        }

        if (isset($parsedChallenge['rspauth'])) {
            return '';
        }

        $cnonce         = $this->generateCnonce();
        $digestUri      = sprintf('%s/%s', $service, $hostname);
        $responseValue = $this->getResponseValue(
            $authcid,
            $pass,
            $parsedChallenge['realm'],
            $parsedChallenge['nonce'],
            $cnonce,
            $digestUri,
            $authzid
        );

        $realm  = '';
        if ($parsedChallenge['realm']) {
            $realm = 'realm="' . $parsedChallenge['realm'] . '",';
        }

        return sprintf(
            'username="%s",%s%snonce="%s",cnonce="%s",nc=00000001,qop=auth,digest-uri="%s",'
            . 'response=%s,maxbuf=%d',
            $authcid,
            $realm,
            $authzidString,
            $parsedChallenge['nonce'],
            $cnonce,
            $digestUri,
            $responseValue,
            $parsedChallenge['maxbuf']
        );
    }

    /**
     * Parses and verifies the digest challenge*
     *
     * @param  string $challenge The digest challenge
     * @return array             The parsed challenge as an assoc
     *                           array in the form "directive => value".
     * @access private
     */
    private function parseChallenge($challenge)
    {
        /**
         * Defaults and required directives
         */
        $tokens  = array(
            'realm'  => '',
            'maxbuf' => 65536,
        );

        $matches = array();
        while (preg_match('/^(?<key>[a-z-]+)=(?<value>"[^"]+(?<!\\\)"|[^,]+)/i', $challenge, $matches)) {
            $match = $matches[0];
            $key   = $matches['key'];
            $value = $matches['value'];

            $this->checkToken($tokens, $key, $value);

            // Remove the just parsed directive from the challenge
            $challenge = substr($challenge, strlen($match) + 1);
        }

        // Required: nonce, algorithm
        if ((empty($tokens['nonce']) || empty($tokens['algorithm'])) && !empty($tokens['rspauth'])) {
            return array();
        }

        return $tokens;
    }

    /**
     * Check found token.
     *
     * @param array  $tokens
     * @param string $key
     * @param string $value
     */
    private function checkToken(array &$tokens, $key, $value)
    {
        // Ignore these as per rfc2831
        if ($key !== 'opaque' && $key !== 'domain') {
            if (!empty($tokens[$key])) {
                // Allowed multiple "realm" and "auth-param"
                if ('realm' === $key || 'auth-param' === $key) {

                    // we don't support multiple realms yet
                    if ('realm' === $key) {
                        throw new RuntimeException('Multiple realms are not supported');
                    }

                    $tokens[$key] = (array) $tokens[$key];
                    $tokens[$key][] = $this->trim($value);

                    // Any other multiple instance = failure
                } else {
                    return array();
                }
            } else {
                $tokens[$key] = $this->trim($value);
            }
        }
    }

    /**
     *
     * @param string $string
     * @return string
     */
    private function trim($string)
    {
        return trim($string, '"');
    }

    /**
     * Creates the response= part of the digest response
     *
     * @param  string $authcid    Authentication id (username)
     * @param  string $pass       Password
     * @param  string $realm      Realm as provided by the server
     * @param  string $nonce      Nonce as provided by the server
     * @param  string $cnonce     Client nonce
     * @param  string $digest_uri The digest-uri= value part of the response
     * @param  string $authzid    Authorization id
     * @return string             The response= part of the digest response
     * @access private
     */
    private function getResponseValue($authcid, $pass, $realm, $nonce, $cnonce, $digest_uri, $authzid = '')
    {
        if ($authzid == '') {
            $A1 = sprintf('%s:%s:%s', pack('H32', md5(sprintf('%s:%s:%s', $authcid, $realm, $pass))), $nonce, $cnonce);
        } else {
            $A1 = sprintf('%s:%s:%s:%s', pack('H32', md5(sprintf('%s:%s:%s', $authcid, $realm, $pass))), $nonce, $cnonce, $authzid);
        }
        $A2 = 'AUTHENTICATE:' . $digest_uri;
        return md5(sprintf('%s:%s:00000001:%s:auth:%s', md5($A1), $nonce, $cnonce, md5($A2)));
    }
}
