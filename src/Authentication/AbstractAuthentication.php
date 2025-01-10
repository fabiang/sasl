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

use Fabiang\SASL\Options;

/**
 * Common functionality to SASL mechanisms
 *
 * @author Richard Heyes <richard@php.net>
 */
abstract class AbstractAuthentication
{
    /**
     * Use random devices.
     */
    public static bool $useDevRandom    = true;
    private static array $randomDevices = ['/dev/urandom', '/dev/random'];

    public function __construct(protected Options $options)
    {
        $this->options = $options;
    }

    /**
     * Get options object.
     */
    public function getOptions(): Options
    {
        return $this->options;
    }

    /**
     * Creates the client nonce for the response
     *
     * @return string The cnonce value
     */
    protected function generateCnonce(): string
    {
        foreach (self::$randomDevices as $file) {
            if (true === static::$useDevRandom && is_readable($file)) {
                $rand = file_get_contents($file, false, null, 0, 32);
                if ($rand !== false) {
                    return base64_encode($rand);
                }
            }
        }

        $cnonce = '';
        for ($i = 0; $i < 32; $i++) {
            $cnonce .= chr(mt_rand(0, 255));
        }

        return base64_encode($cnonce);
    }

    /**
     * Generate downgrade protection string
     */
    protected function generateDowngradeProtectionVerification(string $groupDelimiter, string $delimiter): string
    {
        $downgradeProtectionOptions = $this->options->getDowngradeProtection();
        if ($downgradeProtectionOptions === null) {
            return '';
        }

        $allowedMechanisms      = $downgradeProtectionOptions->getAllowedMechanisms();
        $allowedChannelBindings = $downgradeProtectionOptions->getAllowedChannelBindings();

        if (count($allowedMechanisms) === 0 && count($allowedChannelBindings) === 0) {
            return '';
        }

        usort($allowedMechanisms, $this->sortOctetCollation(...));
        usort($allowedChannelBindings, $this->sortOctetCollation(...));

        $protect = implode($delimiter, $allowedMechanisms);
        if (count($allowedChannelBindings) > 0) {
            $protect .= $groupDelimiter . implode($delimiter, $allowedChannelBindings);
        }
        return $protect;
    }

    /**
     * @link https://datatracker.ietf.org/doc/html/rfc4790#page-22
     */
    private function sortOctetCollation(string $a, string $b): int
    {
        if ($a == $b) {
            return 0;
        }
        return ($a < $b) ? -1 : 1;
    }
}
