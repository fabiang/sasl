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

use Fabiang\SASL\Options\DowngradeProtectionOptions;

/**
 * Options object for Sasl.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class Options
{
    /**
     * Constructor.
     *
     * @param string $authcid  authentication identity (e.g. username)
     * @param string $secret   authentication secret (e.g. password)
     * @param string $authzid  authorization identity (username to proxy as)
     * @param string $service  service name
     * @param string $hostname service hostname
     * @param DowngradeProtectionOptions $downgradeProtection Options for SCRAM-SHA*'s downgrade protection
     */
    public function __construct(
        protected ?string $authcid = null,
        #[\SensitiveParameter]
        protected ?string $secret = null,
        protected ?string $authzid = null,
        protected ?string $service = null,
        protected ?string $hostname = null,
        protected ?DowngradeProtectionOptions $downgradeProtection = null
    ) {
    }

    public function getAuthcid(): ?string
    {
        return $this->authcid;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function getAuthzid(): ?string
    {
        return $this->authzid;
    }

    public function getService(): ?string
    {
        return $this->service;
    }

    public function getHostname(): ?string
    {
        return $this->hostname;
    }

    public function getDowngradeProtection(): ?DowngradeProtectionOptions
    {
        return $this->downgradeProtection;
    }
}
