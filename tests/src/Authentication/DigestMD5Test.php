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
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */

namespace Fabiang\SASL\Authentication;

use PHPUnit\Framework\TestCase;
use Fabiang\SASL\Options;
use Fabiang\SASL\Exception\InvalidArgumentException;
use Fabiang\SASL\Exception\RuntimeException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;

#[CoversClass(DigestMD5::class)]
#[UsesClass(Options::class)]
#[UsesClass(AbstractAuthentication::class)]
final class DigestMD5Test extends TestCase
{
    protected DigestMD5 $object;
    protected Options $options;

    protected function setUp(): void
    {
        $this->options = new Options('authcid', 'pass', 'authzid', 'service', 'hostname');
        $this->object = new DigestMD5($this->options);
    }

    #[Test]
    public function getResponseRealm(): void
    {
         $this->assertMatchesRegularExpression(
             '#^username="authcid",realm="localhost",authzid="authzid",'
             . 'nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'realm="localhost",nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,'
                 . 'auth-param=1,auth-param=2'
             )
         );
    }

    #[Test]
    public function getResponseWithMultipleRealms(): void
    {
        $this->expectException(RuntimeException::class);
        $this->object->createResponse('realm="localhost",realm="phpunit"');
    }

    #[Test]
    public function getResponseRealmWithoutDevRandom(): void
    {
        DigestMD5::$useDevRandom = false;

         $this->assertMatchesRegularExpression(
             '#^username="authcid",realm="localhost",authzid="authzid",'
             . 'nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'realm="localhost",nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess'
             )
         );

        DigestMD5::$useDevRandom = true;
    }

    #[Test]
    public function getResponseNoRealm(): void
    {
         $this->assertMatchesRegularExpression(
             '#^username="authcid",authzid="authzid",nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,opaque=1,domain=2'
             )
         );
    }

    #[Test]
    public function getResponseNoAuthzid(): void
    {
        $options = new Options('authcid', 'pass', '', 'service', 'hostname');
        $object  = new DigestMD5($options);

        $this->assertMatchesRegularExpression(
            '#^username="authcid",nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,' .
            'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
            $object->createResponse(
                'nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,opaque=1,domain=2'
            )
        );
    }

    #[Test]
    public function getResponseInvalidChallenge(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->object->createResponse('invalid_challenge');
    }

    #[Test]
    public function parseChallengeNotAllowiedMultiples(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->object->createResponse('qop=1,qop=2');
    }
}
