<?php

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014-2024 Fabian Grutschus
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

namespace Fabiang\Sasl\Authentication;

use Fabiang\Sasl\TestCase;
use Fabiang\Sasl\Options;

/**
 * Generated by PHPUnit_SkeletonGenerator on 2014-12-05 at 13:44:41.
 *
 * @coversDefaultClass Fabiang\Sasl\Authentication\DigestMD5
 */
class DigestMD5Test extends TestCase
{
    /**
     * @var DigestMD5
     */
    protected $object;

    /**
     * @var Options
     */
    protected $options;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp(): void
    {
        $this->options = new Options('authcid', 'pass', 'authzid', 'service', 'hostname');
        $this->object = new DigestMD5($this->options);
    }

    /**
     * @covers ::createResponse
     * @covers ::parseChallenge
     * @covers ::checkToken
     * @covers ::getResponseValue
     * @covers ::generateCnonce
     * @covers ::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseRealm()
    {
         $this->assertMatchesRegularExpressionCompat(
             '#^username="authcid",realm="localhost",authzid="authzid",'
             . 'nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'realm="localhost",nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,'
                 . 'auth-param=1,auth-param=2'
             )
         );
    }

    /**
     * @covers ::checkToken
     * @uses Fabiang\Sasl\Authentication\DigestMD5::createResponse
     * @uses Fabiang\Sasl\Authentication\DigestMD5::parseChallenge
     * @uses Fabiang\Sasl\Authentication\DigestMD5::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseWithMultipleRealms()
    {
        $this->expectEx('Fabiang\Sasl\Exception\RuntimeException');
        $this->object->createResponse('realm="localhost",realm="phpunit"');
    }

    /**
     * @covers ::createResponse
     * @covers ::checkToken
     * @covers ::parseChallenge
     * @covers ::getResponseValue
     * @covers ::generateCnonce
     * @covers ::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseRealmWithoutDevRandom()
    {
        DigestMD5::$useDevRandom = false;

         $this->assertMatchesRegularExpressionCompat(
             '#^username="authcid",realm="localhost",authzid="authzid",'
             . 'nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'realm="localhost",nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess'
             )
         );

        DigestMD5::$useDevRandom = true;
    }

    /**
     * @covers ::createResponse
     * @covers ::parseChallenge
     * @covers ::checkToken
     * @covers ::getResponseValue
     * @covers ::generateCnonce
     * @covers ::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseNoRealm()
    {
         $this->assertMatchesRegularExpressionCompat(
             '#^username="authcid",authzid="authzid",nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $this->object->createResponse(
                 'nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,opaque=1,domain=2'
             )
         );
    }

    /**
     * @covers ::createResponse
     * @covers ::parseChallenge
     * @covers ::checkToken
     * @covers ::getResponseValue
     * @covers ::generateCnonce
     * @covers ::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseNoAuthzid()
    {
        $options = new Options('authcid', 'pass', '', 'service', 'hostname');
        $object  = new DigestMD5($options);

         $this->assertMatchesRegularExpressionCompat(
             '#^username="authcid",nonce="abcdefghijklmnopqrstuvw",cnonce="[^"]+",nc=00000001,'
             . 'qop=auth,digest-uri="service/hostname",response=[^,]+,maxbuf=65536$#',
             $object->createResponse(
                 'nonce="abcdefghijklmnopqrstuvw",qop="auth",charset=utf-8,algorithm=md5-sess,opaque=1,domain=2'
             )
         );
    }

    /**
     * @covers ::createResponse
     * @covers ::parseChallenge
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetResponseInvalidChallenge()
    {
        $this->expectEx('Fabiang\Sasl\Exception\InvalidArgumentException');
        $this->object->createResponse('invalid_challenge');
    }

    /**
     * @covers ::createResponse
     * @covers ::parseChallenge
     * @covers ::checkToken
     * @covers ::trim
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testParseChallengeNotAllowiedMultiples()
    {
        $this->expectEx('Fabiang\Sasl\Exception\InvalidArgumentException');
        $this->object->createResponse('qop=1,qop=2');
    }

    private function expectEx($exception)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exception);
        } else {
            $this->setExpectedException($exception);
        }
    }
}
