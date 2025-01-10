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

namespace Fabiang\SASL;

use PHPUnit\Framework\TestCase;
use Fabiang\SASL\Options;
use Fabiang\SASL\Authentication;
use Fabiang\SASL\Authentication\AbstractAuthentication;
use Fabiang\SASL\Exception\UnsupportedMechanismException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(SASL::class)]
#[CoversClass(AbstractAuthentication::class)]
#[UsesClass(Authentication\SCRAM::class)]
#[UsesClass(Options::class)]
#[UsesClass(Options\DowngradeProtectionOptions::class)]
final class SASLTest extends TestCase
{
    #[Test()]
    #[DataProvider('provideMechanisms')]
    public function fromString(
        string $expectedInstance,
        SASL $mechanism,
        string $mechanismString,
        ?string $hashAlgo
    ): void {
        $actualInstance = SASL::fromString($mechanismString);
        $this->assertSame($mechanism, $actualInstance);
    }

    #[Test()]
    public function fromStringInvalid(): void
    {
        $this->expectException(UnsupportedMechanismException::class);
        SASL::fromString('INVALID');
    }

    #[Test()]
    public function fromStringInvalidPlus(): void
    {
        $this->expectException(UnsupportedMechanismException::class);
        SASL::fromString('SCRAM-SHA-256-PLUS');
    }

    /**
     * @param string                  $expectedInstance Expected object instance
     * @param AuthenticationMechanism $mechanism        Authentication mechanism
     * @param string                  $hashAlgo         Expected hash alogrithm (for SCRAM)
     */
    #[Test]
    #[DataProvider('provideMechanisms')]
    public function mechanism(
        string $expectedInstance,
        SASL $mechanism,
        string $mechanismString,
        ?string $hashAlgo
    ): void {
        $object = $mechanism->mechanism([
            'authcid'              => 'testuser',
            'hostname'             => 'hostname',
            'service'              => 'servicename',
            'secret'               => 'mysecret',
            'authzid'              => 'authzid',
            'downgrade_protection' => [
                'allowed_mechanisms'       => ['X-TEST'],
                'allowed_channel_bindings' => ['tls-unique'],
            ],
        ]);

        $this->assertInstanceOf($expectedInstance, $object);
        $this->assertInstanceOf(Options::class, $object->getOptions());
        $this->assertSame('testuser', $object->getOptions()->getAuthcid());
        $this->assertSame('mysecret', $object->getOptions()->getSecret());
        $this->assertSame('authzid', $object->getOptions()->getAuthzid());
        $this->assertSame('servicename', $object->getOptions()->getService());
        $this->assertSame('hostname', $object->getOptions()->getHostname());

        $this->assertSame(['X-TEST'], $object->getOptions()
            ->getDowngradeProtection()
            ->getAllowedMechanisms());
        $this->assertSame(['tls-unique'], $object->getOptions()
            ->getDowngradeProtection()
            ->getAllowedChannelBindings());

        if (null !== $hashAlgo) {
            $this->assertInstanceOf('Fabiang\SASL\Authentication\SCRAM', $object);
            $this->assertSame($hashAlgo, $object->getHashAlgo());
        }
    }

    /**
     * @param string $expectedInstance  Expected object instance
     * @param string SASL               Authentication mechanism
     * @param string $hashAlgo          Expected hash alogrithm (for SCRAM)
     */
    #[Test]
    #[DataProvider('provideMechanisms')]
    public function mechainsmZeroStringValues(
        string $expectedInstance,
        SASL $mechanism,
        string $mechanismString,
        ?string $hashAlgo
    ): void {
        $object = $mechanism->mechanism([
            'authcid'  => '0',
            'hostname' => '0',
            'service'  => '0',
            'secret'   => '0',
            'authzid'  => '0'
        ]);

        $this->assertInstanceOf($expectedInstance, $object);
        $this->assertInstanceOf(Options::class, $object->getOptions());
        $this->assertSame('0', $object->getOptions()->getAuthcid());
        $this->assertSame('0', $object->getOptions()->getSecret());
        $this->assertSame('0', $object->getOptions()->getAuthzid());
        $this->assertSame('0', $object->getOptions()->getService());
        $this->assertSame('0', $object->getOptions()->getHostname());
    }

    #[Test]
    public function factoryWithOptionsArray(): void
    {
        $mechanism = SASL::Login;
        $object = $mechanism->mechanism([
            'authcid'  => 'testuser',
            'hostname' => 'hostname',
            'service'  => 'servicename',
            'secret'   => 'mysecret',
        ]);
        $this->assertNull($object->getOptions()->getAuthzid());
    }

    #[Test]
    public function factoryWithOptionsObject(): void
    {
        $mechanism = SASL::Login;
        $options = new Options('test', 'secret');
        $object  = $mechanism->mechanism($options);
        $this->assertSame($options, $object->getOptions());
    }

    public static function provideMechanisms(): array
    {
        return [
            [
                'expectedInstance' => Authentication\Anonymous::class,
                'mechanism'        => SASL::Anonymous,
                'mechanismString'  => 'Anonymous',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\Login::class,
                'mechanism'        => SASL::Login,
                'mechanismString'  => 'LOGIN',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\Plain::class,
                'mechanism'        => SASL::Plain,
                'mechanismString'  => 'plain',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\External::class,
                'mechanism'        => SASL::External,
                'mechanismString'  => 'external',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\CramMD5::class,
                'mechanism'        => SASL::CramMD5,
                'mechanismString'  => 'cram-md5',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\DigestMD5::class,
                'mechanism'        => SASL::DigestMD5,
                'mechanismString'  => 'DigestMD5',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\DigestMD5::class,
                'mechanism'        => SASL::DigestMD5,
                'mechanismString'  => 'Digest-MD5',
                'hashAlgo'         => null,
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA_1,
                'mechanismString'  => 'SCRAM-SHA-1',
                'hashAlgo'         => 'sha1',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA_224,
                'mechanismString'  => 'SCRAM-SHA-224',
                'hashAlgo'         => 'sha224',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA_256,
                'mechanismString'  => 'SCRAM-SHA-256',
                'hashAlgo'         => 'sha256',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA_384,
                'mechanismString'  => 'SCRAM-SHA-384',
                'hashAlgo'         => 'sha384',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA_512,
                'mechanismString'  => 'SCRAM-SHA-512',
                'hashAlgo'         => 'sha512',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA3_224,
                'mechanismString'  => 'SCRAM-SHA3-224',
                'hashAlgo'         => 'sha3-224',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA3_256,
                'mechanismString'  => 'SCRAM-SHA3-256',
                'hashAlgo'         => 'sha3-256',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA3_384,
                'mechanismString'  => 'SCRAM-SHA3-384',
                'hashAlgo'         => 'sha3-384',
            ],
            [
                'expectedInstance' => Authentication\SCRAM::class,
                'mechanism'        => SASL::SCRAM_SHA3_512,
                'mechanismString'  => 'SCRAM-SHA3-512',
                'hashAlgo'         => 'sha3-512',
            ],
        ];
    }
}
