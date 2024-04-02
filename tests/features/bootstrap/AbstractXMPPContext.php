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

namespace Fabiang\Sasl\Behat;

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use Fabiang\Sasl\Sasl;
use Fabiang\Sasl\Options;
use Fabiang\Sasl\Options\DowngradeProtectionOptions;

/**
 * Description of AbstractXMPPContext
 *
 * @author fabian.grutschus
 */
abstract class AbstractXMPPContext extends AbstractContext implements Context, SnippetAcceptingContext
{
    /**
     * @var string
     */
    protected $domain;

    /**
     * @var string
     */
    protected $tlsversion;

    /**
     * @var \Fabiang\Sasl\Authentication\AuthenticationInterface
     */
    protected $authenticationObject;

    /**
     * @var Sasl
     */
    protected $authenticationFactory;

    protected $mechanisms = array();
    protected $channelBindings = array();

    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     *
     * @param string  $hostname Hostname for connection
     * @param integer $port
     * @param string  $domain
     * @param string  $username Domain name of server (important for connecting)
     * @param string  $password
     * @param string  $logdir
     * @param string  $tlsversion
     */
    public function __construct(
        $hostname,
        $port,
        $domain,
        $username,
        $password,
        $logdir,
        $tlsversion = 'tlsv1.2'
    ) {
        $this->hostname = $hostname;
        $this->port     = (int) $port;
        $this->domain   = $domain;
        $this->username = $username;
        $this->password = $password;

        if (!is_dir($logdir)) {
            mkdir($logdir, 0777, true);
        }

        $this->authenticationFactory = new Sasl;
        $this->logdir = $logdir;

        $this->tlsversion = $tlsversion;
    }

    protected function getOptions()
    {
        return new Options(
            $this->username,
            $this->password,
            null,
            'xmpp',
            $this->domain,
            new DowngradeProtectionOptions($this->mechanisms, $this->channelBindings)
        );
    }
}
