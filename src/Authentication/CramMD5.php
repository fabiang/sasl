<?php

declare(strict_types=1);

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014-2025 Fabian Grutschus
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

namespace Fabiang\SASL\Authentication;

use Fabiang\SASL\Authentication\AbstractAuthentication;
use Deprecated;
use Override;

/**
 * Implmentation of CRAM-MD5 SASL mechanism
 *
 * @author Richard Heyes <richard@php.net>
 */
class CramMD5 extends AbstractAuthentication implements ChallengeAuthenticationInterface
{
    /**
     * Implements the CRAM-MD5 SASL mechanism
     * This DOES NOT base64 encode the return value,
     * you will need to do that yourself.
     *
     * @param string|null $challenge The challenge supplied by the server.
     *                          this should be already base64_decoded.
     *
     * @return string|false The string to pass back to the server, of the form
     *                "<user> <digest>". This is NOT base64_encoded.
     */
    #[Deprecated(message: "CramMD5 authentication mechanism is insecure", since: "2.0")]
    #[Override]
    public function createResponse(?string $challenge = null): string|false
    {
        $authcid = $this->options->getAuthcid();
        $secret  = $this->options->getSecret();

        if ($authcid === null || $secret === null || $challenge === null
            || $authcid === '' || $secret === '' || $challenge === '') {
            return false;
        }

        return $authcid . ' ' . hash_hmac('md5', $challenge, $secret);
    }
}
