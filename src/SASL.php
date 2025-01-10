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

namespace Fabiang\SASL;

use Fabiang\SASL\Exception\InvalidArgumentException;
use Fabiang\SASL\Exception\UnsupportedMechanismException;
use Fabiang\SASL\Options\DowngradeProtectionOptions;
use Fabiang\SASL\Authentication\AuthenticationInterface;
use Fabiang\SASL\Options;
use Fabiang\SASL\Authentication;
use Fabiang\SASL\Authentication\SCRAM;

/**
 * Client implementation of various SASL mechanisms
 *
 * @author Richard Heyes <richard@php.net>
 */
enum SASL: string
{
    case Anonymous = 'ANONYMOUS';
    case Login     = 'LOGIN';
    case Plain     = 'PLAIN';
    case External  = 'EXTERNAL';
    case CramMD5   = 'CRAMMD5';
    case DigestMD5 = 'DIGESTMD5';

    case SCRAM_SHA_1    = 'SCRAM-SHA-1';
    case SCRAM_SHA_224  = 'SCRAM-SHA-224';
    case SCRAM_SHA_256  = 'SCRAM-SHA-256';
    case SCRAM_SHA_384  = 'SCRAM-SHA-384';
    case SCRAM_SHA_512  = 'SCRAM-SHA-512';
    case SCRAM_SHA3_224 = 'SCRAM-SHA3-224';
    case SCRAM_SHA3_256 = 'SCRAM-SHA3-256';
    case SCRAM_SHA3_384 = 'SCRAM-SHA3-384';
    case SCRAM_SHA3_512 = 'SCRAM-SHA3-512';

    /**
     * @throws UnsupportedMechanismException
     */
    public static function fromString(string $authenticationType): static
    {
        $formatedType = strtolower(str_replace('-', '', $authenticationType));

        return match ($formatedType) {
            'anonymous'    => static::Anonymous,
            'login'        => static::Login,
            'plain'        => static::Plain,
            'external'     => static::External,
            'crammd5'      => static::CramMD5,
            'digestmd5'    => static::DigestMD5,
            'scramsha1'    => static::SCRAM_SHA_1,
            'scramsha224'  => static::SCRAM_SHA_224,
            'scramsha256'  => static::SCRAM_SHA_256,
            'scramsha384'  => static::SCRAM_SHA_384,
            'scramsha512'  => static::SCRAM_SHA_512,
            'scramsha3224' => static::SCRAM_SHA3_224,
            'scramsha3256' => static::SCRAM_SHA3_256,
            'scramsha3384' => static::SCRAM_SHA3_384,
            'scramsha3512' => static::SCRAM_SHA3_512,
            default => throw new UnsupportedMechanismException("Invalid SASL mechanism type '$authenticationType'"),
        };
    }

    public function mechanism(Options|array $options = []): AuthenticationInterface
    {
        $options = $this->createOptionsObject($options);

        return match ($this) {
            self::Anonymous      => new Authentication\Anonymous($options),
            self::Login          => new Authentication\Login($options),
            self::Plain          => new Authentication\Plain($options),
            self::External       => new Authentication\External($options),
            self::CramMD5        => new Authentication\CramMD5($options),
            self::DigestMD5      => new Authentication\DigestMD5($options),
            self::SCRAM_SHA_1    => new SCRAM($options, 'sha1'),
            self::SCRAM_SHA_224  => new SCRAM($options, 'sha224'),
            self::SCRAM_SHA_256  => new SCRAM($options, 'sha256'),
            self::SCRAM_SHA_384  => new SCRAM($options, 'sha384'),
            self::SCRAM_SHA_512  => new SCRAM($options, 'sha512'),
            self::SCRAM_SHA3_224 => new SCRAM($options, 'sha3-224'),
            self::SCRAM_SHA3_256 => new SCRAM($options, 'sha3-256'),
            self::SCRAM_SHA3_384 => new SCRAM($options, 'sha3-384'),
            self::SCRAM_SHA3_512 => new SCRAM($options, 'sha3-512'),
        };
    }

    /**
     * @throws InvalidArgumentException
     */
    private function createOptionsObject(Options|array $options): Options
    {
        if ($options instanceof Options) {
            return $options;
        }

        $downgradeProtectOptions = null;
        if (isset($options['downgrade_protection'])) {
            $dpo = $options['downgrade_protection'];

            $allowedMechanisms      = $dpo['allowed_mechanisms'] ?? [];
            $allowedChannelBindings = $dpo['allowed_channel_bindings'] ?? [];

            $downgradeProtectOptions = new DowngradeProtectionOptions($allowedMechanisms, $allowedChannelBindings);
        }

        return new Options(
            $this->checkEmpty($options, 'authcid'),
            $this->checkEmpty($options, 'secret'),
            $this->checkEmpty($options, 'authzid'),
            $this->checkEmpty($options, 'service'),
            $this->checkEmpty($options, 'hostname'),
            $downgradeProtectOptions
        );
    }

    private function checkEmpty(array $array, string $key): mixed
    {
        return $array[$key] ?? null;
    }
}
