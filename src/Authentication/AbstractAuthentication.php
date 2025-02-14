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
 * @author Richard Heyes <richard@php.net>
 */

namespace Fabiang\Sasl\Authentication;

use Fabiang\Sasl\Options;

/**
 * Common functionality to SASL mechanisms
 *
 * @author Richard Heyes <richard@php.net>
 */
abstract class AbstractAuthentication
{
    /**
     * Use random devices.
     *
     * @var bool
     */
    public static $useDevRandom = true;

    /**
     * Options object.
     *
     * @var Options
     */
    protected $options;

    /**
     *
     * @param Options $options
     */
    public function __construct(Options $options)
    {
        $this->options = $options;
    }

    /**
     * Get options object.
     *
     * @return Options
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * Creates the client nonce for the response
     *
     * @return string The cnonce value
     */
    protected function generateCnonce()
    {
        foreach (array('/dev/urandom', '/dev/random') as $file) {
            if (true === static::$useDevRandom && is_readable($file)) {
                return base64_encode(file_get_contents($file, false, null, 0, 32));
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
     *
     * @return string
     */
    protected function generateDowngradeProtectionVerification()
    {
        $downgradeProtectionOptions = $this->options->getDowngradeProtection();

        $allowedMechanisms      = $downgradeProtectionOptions->getAllowedMechanisms();
        $allowedChannelBindings = $downgradeProtectionOptions->getAllowedChannelBindings();

        if (count($allowedMechanisms) === 0 && count($allowedChannelBindings) === 0) {
            return '';
        }

        usort($allowedMechanisms, array($this, 'sortOctetCollation'));
        usort($allowedChannelBindings, array($this, 'sortOctetCollation'));

        $protect = implode("\x1e", $allowedMechanisms);
        if (count($allowedChannelBindings) > 0) {
            $protect .= "\x1f" . implode("\x1e", $allowedChannelBindings);
        }
        return $protect;
    }

    /**
     * @param string $a
     * @param string $b
     * @return int
     * @link https://datatracker.ietf.org/doc/html/rfc4790#page-22
     */
    private function sortOctetCollation($a, $b)
    {
        if ($a == $b) {
            return 0;
        }
        return ($a < $b) ? -1 : 1;
    }
}
