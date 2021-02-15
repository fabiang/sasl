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

namespace Fabiang\Sasl\Behat;

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use PHPUnit\Framework\Assert;
use Fabiang\Sasl\Sasl;
use Fabiang\Sasl\Options;

/**
 * Defines application features from the specific context.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class XmppContext extends AbstractContext implements Context, SnippetAcceptingContext
{

    protected $hostname;
    protected $port;
    protected $domain;
    protected $username;
    protected $password;

    /**
     * @var \Fabiang\Sasl\Authentication\AuthenticationInterface
     */
    protected $authenticationObject;

    /**
     * @var Sasl
     */
    protected $authenticationFactory;

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
     */
    public function __construct($hostname, $port, $domain, $username, $password, $logdir)
    {
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
    }

    /**
     * @Given Connection to xmpp server
     */
    public function connectionToXmppServer()
    {
        $this->connect();

        $this->write(
            '<?xml version="1.0" encoding="UTF-8"?><stream:stream to="' . $this->domain
            . '" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" version="1.0">'
        );
    }

    /**
     * @Given xmpp server supports authentication method :authenticationMethod
     */
    public function xmppServerSupportsAuthenticationMethod($authenticationMethod)
    {
        $data = $this->readStreamUntil('</stream:features>');
        Assert::assertContains("<mechanism>$authenticationMethod</mechanism>", $data);
    }

    /**
     * @When authenticate with method PLAIN
     */
    public function authenticateWithMethodPlain()
    {
        $authenticationObject = $this->authenticationFactory->factory(
            'PLAIN',
            new Options($this->username, $this->password)
        );
        $authenticationData   = $authenticationObject->createResponse();
        $this->write(
            '<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">'
            . base64_encode($authenticationData) . '</auth>'
        );
    }

    /**
     * @When authenticate with method DIGEST-MD5
     */
    public function authenticateWithMethodDigestMd5()
    {
        $this->write("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='DIGEST-MD5'/>");
    }

    /**
     * @When authenticate with method SCRAM-SHA-1
     */
    public function authenticateWithMethodScramSha1()
    {
        $this->authenticationObject = $this->authenticationFactory->factory(
            'scram-sha-1',
            new Options($this->username, $this->password)
        );

        $authData = base64_encode($this->authenticationObject->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>$authData</auth>"
        );
    }

    /**
     * @When responde to challenge received for DIGEST-MD5
     */
    public function respondeToChallengeReceivedForDigestMd5()
    {
        $data = $this->readStreamUntil('</challenge>');
        Assert::assertRegExp("#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#", $data);

        $authenticationObject = $this->authenticationFactory->factory('DIGEST-MD5', new Options(
            $this->username,
            $this->password,
            null,
            'xmpp',
            $this->domain
        ));

        $challenge = substr($data, 52, -12);

        $response = $authenticationObject->createResponse(base64_decode($challenge));

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($response) . "</response>"
        );
    }

    /**
     * @When responde to rspauth challenge
     */
    public function respondeToRspauthChallenge()
    {
        $data = $this->readStreamUntil('</challenge>');

        $challenge = base64_decode(substr($data, 52, -12));

        Assert::assertRegExp('/^rspauth=.+$/', $challenge);

        $this->write("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    }

    /**
     * @When responde to challenge for SCRAM-SHA-1
     */
    public function respondeToChallengeForScramSha1()
    {
        $data = $this->readStreamUntil('</challenge>');
        Assert::assertRegExp("#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#", $data);

        $challenge = base64_decode(substr($data, 52, -12));

        $authData = $this->authenticationObject->createResponse($challenge);

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($authData) . "</response>"
        );
    }

    /**
     * @Then should be authenticated at xmpp server
     */
    public function shouldBeAuthenticatedAtXmppServer()
    {
        $data = $this->read();
        Assert::assertSame("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", $data);
    }

    /**
     * @Then should be authenticated at xmpp server with verification
     */
    public function shouldBeAuthenticatedAtXmppServerWithVerification()
    {
        $data = $this->read();
        Assert::assertRegExp("#^<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</success>$#", $data);

        $verfication = base64_decode(substr($data, 50, -10));

        Assert::assertTrue($this->authenticationObject->verify($verfication));
    }
}
