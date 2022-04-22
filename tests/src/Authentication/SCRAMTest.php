<?php

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014-2022 Fabian Grutschus
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

use PHPUnit\Framework\TestCase;
use Fabiang\Sasl\Options;

/**
 * Generated by PHPUnit_SkeletonGenerator on 2014-12-05 at 15:17:47.
 *
 * @coversDefaultClass Fabiang\Sasl\Authentication\SCRAM
 */
class SCRAMTest extends TestCase
{
    /**
     * @var SCRAM
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
        $this->options = new Options('test', 'pass', 'zid');
        $this->object  = new SCRAM($this->options, 'md5');
    }

    /**
     * @covers ::__construct
     * @covers ::getHashAlgo
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testConstructor()
    {
        $object = new SCRAM(new Options('test'), 'sha-1');
        $this->assertSame('sha1', $object->getHashAlgo());
    }

    /**
     * @covers ::__construct
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     * @expectedExceptionMessage Invalid SASL mechanism type 'test'
     */
    public function testConstructorWithInvalidHash()
    {
        $this->expectEx('Fabiang\Sasl\Exception\InvalidArgumentException');
        new SCRAM(new Options('test'), 'test');
    }

    /**
     * @covers ::createResponse
     * @covers ::generateCnonce
     * @covers ::formatName
     * @covers ::generateInitialResponse
     * @covers ::__construct
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetInitialResponse()
    {
        $options = new Options('u,=ser', 'pass', 'authzid');
        $object  = new SCRAM($options, 'md5');
        $this->assertRegExp(
            '#^n,a=authzid,n=u=2C=3Dser,r=[a-z0-9A-Z=+/]+$#',
            $object->createResponse(null)
        );
    }

    /**
     * @covers ::createResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::__construct
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testGetInitialResponseAuthCidIsEmpty()
    {
        $options = new Options('');
        $object  = new SCRAM($options, 'md5');
        $this->assertFalse($object->createResponse(null));
    }

    /**
     * @covers ::createResponse
     * @covers ::generateResponse
     * @covers ::hi
     * @covers ::getCnonce
     * @covers ::__construct
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Authentication\SCRAM::generateInitialResponse
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::generateCnonce
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testCreateResponseGenerateResponse()
    {
        $this->object->createResponse(null);

        $this->assertRegExp(
            '#^c=[a-zA-Z0-9=+/]+,r=[a-zA-Z0-9=+/]+,p=[a-zA-Z0-9=+/]+$#',
            $this->object->createResponse('r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,a=2')
        );

        $this->assertRegExp('#^[a-zA-Z0-9=+/]+$#', $this->object->getCnonce());
    }

    /**
     * @covers ::generateResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::__construct
     * @uses Fabiang\Sasl\Authentication\SCRAM::createResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testCreateResponseChallengeIsWrong()
    {
        $this->assertFalse($this->object->createResponse('test'));
    }

    /**
     * @covers ::generateResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::__construct
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Authentication\SCRAM::generateInitialResponse
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::generateCnonce
     * @uses Fabiang\Sasl\Authentication\SCRAM::createResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Authentication\SCRAM::getCnonce
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testCreateResponseCnonceInvalid()
    {
        $this->object->createResponse(null);

        $this->assertFalse($this->object->createResponse('r=aaa,s=abcdefg=,i=1,a=2'));
    }

    /**
     * @covers ::verify
     * @covers ::getAuthMessage
     * @covers ::getSaltedPassword
     * @uses Fabiang\Sasl\Authentication\SCRAM::createResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::generateResponse
     * @uses Fabiang\Sasl\Authentication\SCRAM::hi
     * @uses Fabiang\Sasl\Authentication\SCRAM::getCnonce
     * @uses Fabiang\Sasl\Authentication\SCRAM::__construct
     * @uses Fabiang\Sasl\Authentication\SCRAM::formatName
     * @uses Fabiang\Sasl\Authentication\SCRAM::generateInitialResponse
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::generateCnonce
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testVerify()
    {
        $this->object->createResponse(null);
        $this->object->createResponse('r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,a=2');

        $serverKey       = hash_hmac('md5', "Server Key", $this->object->getSaltedPassword(), true);
        $serverSignature = hash_hmac('md5', $this->object->getAuthMessage(), $serverKey, true);

        $this->assertTrue($this->object->verify('v=' . base64_encode($serverSignature)));
    }

    /**
     * @covers ::verify
     * @uses Fabiang\Sasl\Authentication\SCRAM::__construct
     * @uses Fabiang\Sasl\Options
     * @uses Fabiang\Sasl\Authentication\AbstractAuthentication::__construct
     */
    public function testVerifyNoResponseBefore()
    {
        $this->assertFalse($this->object->verify(''));
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
