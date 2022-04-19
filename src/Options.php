<?php

/**
 * Sasl library.
 *
 * Copyright (c) 2002-2003 Richard Heyes,
 *               2014-2021 Fabian Grutschus
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

namespace Fabiang\Sasl;

/**
 * Options object for Sasl.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class Options
{
    /**
     * Authentication identity (e.g. username).
     *
     * @var string
     */
    protected $authcid;

    /**
     * Authentication secret   (e.g. password)
     *
     * @var string
     */
    protected $secret;

    /**
     * Authorization identity
     *
     * @var string
     */
    protected $authzid;

    /**
     * Service name.
     *
     * @var string
     */
    protected $service;

    /**
     * Service hostname.
     *
     * @var string
     */
    protected $hostname;

    /**
     * Constructor.
     *
     * @param string $authcid  authentication identity (e.g. username)
     * @param string $secret   authentication secret (e.g. password)
     * @param string $authzid  authorization identity (username to proxy as)
     * @param string $service  service name
     * @param string $hostname service hostname
     */
    public function __construct($authcid, $secret = null, $authzid = null, $service = null, $hostname = null)
    {
        $this->authcid  = $authcid;
        $this->secret   = $secret;
        $this->authzid  = $authzid;
        $this->service  = $service;
        $this->hostname = $hostname;
    }

    public function getAuthcid()
    {
        return $this->authcid;
    }

    public function getSecret()
    {
        return $this->secret;
    }

    public function getAuthzid()
    {
        return $this->authzid;
    }

    public function getService()
    {
        return $this->service;
    }

    public function getHostname()
    {
        return $this->hostname;
    }
}
