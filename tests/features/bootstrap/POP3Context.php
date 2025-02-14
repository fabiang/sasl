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

namespace Fabiang\SASL\Behat;

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use Behat\Step\Given;
use Behat\Step\When;
use Behat\Step\Then;
use PHPUnit\Framework\Assert;
use Fabiang\SASL\SASL;
use Fabiang\SASL\AuthenticationMechanism;
use Fabiang\SASL\Options;
use Fabiang\SASL\Authentication\AuthenticationInterface;

/**
 * Defines application features from the specific context.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class POP3Context extends AbstractContext implements Context, SnippetAcceptingContext
{
    protected string $challenge;

    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     *
     * @param string $hostname Hostname for connection
     */
    public function __construct(string $hostname, string $port, string $username, string $password, string $logdir)
    {
        $this->hostname = $hostname;
        $this->port1     = (int) $port;
        $this->username = $username;
        $this->password = $password;

        if (!is_dir($logdir)) {
            mkdir($logdir, 0777, true);
        }

        $this->logdir = $logdir;
    }

    #[Given('Connection to pop3 server')]
    public function connectionToPopServer(): void
    {
        $this->connect($this->port1);
        Assert::assertSame("+OK Dovecot ready.\r\n", $this->read());
    }

    #[Given('challenge received at auth request method :mechanism')]
    public function challengeReceivedAtAuthRequestMethod(string $mechanism): void
    {
        $this->write("AUTH $mechanism\r\n");
        $challenge = $this->read();
        Assert::assertMatchesRegularExpression('/^\+ [a-zA-Z0-9]+/', $challenge);
        $this->challenge = base64_decode(substr(trim($challenge), 2));
    }

    #[When('Autenticate with CRAM-MD5')]
    public function autenticateWithCramMd5(): void
    {
        $mechanism = SASL::CramMD5->mechanism(new Options($this->username, $this->password));
        $response = base64_encode($mechanism->createResponse($this->challenge));
        $this->write("$response\r\n");
    }

    #[Then('should be authenticate at pop3 server')]
    public function shouldBeAuthenticateAtPopServer(): void
    {
        Assert::assertSame("+OK Logged in.\r\n", $this->read());
    }
}
