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
use Fabiang\SASL\Options\DowngradeProtectionOptions;
use Fabiang\SASL\Exception\InvalidArgumentException;
use Fabiang\SASL\Authentication\AbstractAuthentication;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(SCRAM::class)]
#[CoversClass(AbstractAuthentication::class)]
#[UsesClass(Options::class)]
#[UsesClass(DowngradeProtectionOptions::class)]
final class SCRAMTest extends TestCase
{
    protected SCRAM $object;
    protected Options $options;

    protected function setUp(): void
    {
        $this->options = new Options('test', 'pass', 'zid');
        $this->object  = new SCRAM($this->options, 'md5');
    }

    #[Test]
    #[DataProvider('provideOldHashAlgos')]
    public function constructor(string $hash, string $expected): void
    {
        $options = new Options('test', 'secret');
        $object = new SCRAM($options, $hash);
        $this->assertSame($expected, $object->getHashAlgo());
    }

    public static function provideOldHashAlgos(): array
    {
        return [
            [
                'hash'     => 'sha1',
                'expected' => 'sha1',
            ],
            [
                'hash'    => 'sha-1',
                'expected' => 'sha1',
            ],
            [
                'hash'     => 'SHA-1',
                'expected' => 'sha1',
            ],
            [
                'hash'     => 'sha256',
                'expected' => 'sha256',
            ],
            [
                'hash'     => 'sha-256',
                'expected' => 'sha256',
            ],
            [
                'hash'     => 'sha512',
                'expected' => 'sha512',
            ],
            [
                'hash'     => 'sha-512',
                'expected' => 'sha512',
            ],
        ];
    }

    #[Test]
    #[DataProvider('provideNewHashAlgos')]
    public function constructorNewAlogs(string $hash, string $expected): void
    {
        $options = new Options('test', 'foo');
        $object = new SCRAM($options, $hash);
        $this->assertSame($expected, $object->getHashAlgo());
    }

    public static function provideNewHashAlgos(): array
    {
        return [
            [
                'hash'     => 'sha3-256',
                'expected' => 'sha3-256',
            ],
            [
                'hash'     => 'sha3-512',
                'expected' => 'sha3-512',
            ],
            [
                'hash'     => 'sha-3-512',
                'expected' => 'sha3-512',
            ],
        ];
    }

    #[Test]
    public function constructorWithInvalidHash(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SCRAM(new Options('test', 'secret'), 'test');
    }

    #[Test]
    public function getInitialResponse(): void
    {
        $options = new Options('u,=ser', 'pass', 'authzid');
        $object  = new SCRAM($options, 'md5');
        $this->assertMatchesRegularExpression(
            '#^n,a=authzid,n=u=2C=3Dser,r=[a-z0-9A-Z=+/]+$#',
            $object->createResponse(null)
        );
    }

    #[Test]
    public function getInitialResponseSecretEmpty(): void
    {
        $options = new Options('u,=ser', '', '');
        $object  = new SCRAM($options, 'md5');
        $this->assertFalse($object->createResponse(null));
    }

    #[Test]
    public function getInitialResponseAuthCidIsEmpty(): void
    {
        $options = new Options('');
        $object  = new SCRAM($options, 'md5');
        $this->assertFalse($object->createResponse(null));
    }

    #[Test]
    public function createResponseGenerateResponse(): void
    {
        $this->object->createResponse(null);

        $this->assertMatchesRegularExpression(
            '#^c=[a-zA-Z0-9=+/]+,r=[a-zA-Z0-9=+/]+,p=[a-zA-Z0-9=+/]+$#',
            $this->object->createResponse('r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,a=2')
        );

        $this->assertMatchesRegularExpression('#^[a-zA-Z0-9=+/]+$#', $this->object->getCnonce());
    }

    #[Test]
    public function createResponseChallengeIsWrong(): void
    {
        $this->assertFalse($this->object->createResponse('test'));
    }

    #[Test]
    public function createResponseCnonceInvalid(): void
    {
        $this->object->createResponse(null);

        $this->assertFalse($this->object->createResponse('r=aaa,s=abcdefg=,i=1,a=2'));
    }

    #[Test]
    public function createResponseDowngradeProtectionEnabledButInvalid(): void
    {
        $options = new Options(
            'test',
            'pass',
            'zid',
            null,
            null,
            new DowngradeProtectionOptions(['A'], ['B'])
        );

        $object = new SCRAM($options, 'md5');

        $object->createResponse(null);
        $this->assertFalse($object->createResponse('r=' . $object->getCnonce() . ',s=abcdefg=,i=2,d=invalid=,a=2'));
    }

    #[Test]
    public function createResponseDowngradeProtectionSecureEnabledButInvalid(): void
    {
        $options = new Options(
            'test',
            'pass',
            'zid',
            null,
            null,
            new DowngradeProtectionOptions(['A'], ['B'])
        );

        $object = new SCRAM($options, 'md5');

        $object->createResponse(null);
        $this->assertFalse($object->createResponse('r=' . $object->getCnonce() . ',s=abcdefg=,i=2,h=invalid=,a=2'));
    }

    #[Test]
    public function createResponseDowngradeProtectionDisabled(): void
    {
        $options = new Options('test', 'pass', 'zid', null, null, null);
        $object  = new SCRAM($options, 'md5');

        $object->createResponse(null);
        $this->assertNotFalse($object->createResponse('r=' . $object->getCnonce() . ',s=abcdefg=,i=2,d=invalid=,a=2'));
    }

    #[Test]
    public function createResponseDowngradeProtectionSecureDisabled(): void
    {
        $options = new Options('test', 'pass', 'zid', null, null, null);
        $object  = new SCRAM($options, 'md5');

        $object->createResponse(null);
        $this->assertNotFalse($object->createResponse('r=' . $object->getCnonce() . ',s=abcdefg=,i=2,h=invalid=,a=2'));
    }

    #[Test]
    public function createResponseExtraMAttr(): void
    {
        $this->object->createResponse(null);
        $this->assertFalse(
            $this->object->createResponse(
                'r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,m=test,a=2'
            )
        );
    }

    #[Test]
    public function createResponseEmptySalt(): void
    {
        $this->object->createResponse(null);
        $this->assertFalse(
            $this->object->createResponse(
                'r=' . $this->object->getCnonce() . ',s=,i=2'
            )
        );
    }

    #[Test]
    public function verify(): void
    {
        $this->object->createResponse(null);
        $this->object->createResponse('r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,a=2');

        $serverKey       = hash_hmac('md5', "Server Key", $this->object->getSaltedSecret(), true);
        $serverSignature = hash_hmac('md5', $this->object->getAuthMessage(), $serverKey, true);

        $this->assertTrue($this->object->verify('v=' . base64_encode($serverSignature)));
    }

    #[Test]
    public function verifyWithExtraMAttr(): void
    {
        $this->object->createResponse(null);
        $this->object->createResponse('r=' . $this->object->getCnonce() . ',s=abcdefg=,i=2,a=2');

        $serverKey       = hash_hmac('md5', "Server Key", $this->object->getSaltedSecret(), true);
        $serverSignature = hash_hmac('md5', $this->object->getAuthMessage(), $serverKey, true);

        $this->assertFalse($this->object->verify('v=' . base64_encode($serverSignature) . ',m=mustfail'));
    }

    #[Test]
    public function verifyNoResponseBefore(): void
    {
        $this->assertFalse($this->object->verify(''));
    }


    #[Test]
    public function saltedSecretNull(): void
    {
        $this->assertNull($this->object->getSaltedSecret());
    }
}
