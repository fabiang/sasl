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

use PHPUnit\Framework\Assert;
use Fabiang\Sasl\Options;
use Fabiang\Sasl\Options\DowngradeProtectionOptions;
use Behat\Behat\Tester\Exception\PendingException;

/**
 * Defines application features from the specific context.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class XMPPContext extends AbstractXMPPContext
{
    /**
     * @When authenticate with method SCRAM-SHA-1
     */
    public function authenticateWithMethodScramSha1()
    {
        $this->authenticationObject = $this->authenticationFactory->factory(
            'scram-sha-1',
            $this->getOptions()
        );

        $authData = base64_encode($this->authenticationObject->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>$authData</auth>"
        );
    }

    /**
     * @When authenticate with method SCRAM-SHA-256
     */
    public function authenticateWithMethodScramSha256()
    {
        $this->authenticationObject = $this->authenticationFactory->factory(
            'scram-sha-256',
            $this->getOptions()
        );

        $authData = base64_encode($this->authenticationObject->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>$authData</auth>"
        );
    }

    /**
     * @When authenticate with method SCRAM-SHA-512
     */
    public function authenticateWithMethodScramSha512()
    {
        $this->authenticationObject = $this->authenticationFactory->factory(
            'scram-sha-512',
            $this->getOptions()
        );

        $authData = base64_encode($this->authenticationObject->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-512'>$authData</auth>"
        );
    }

    private function sendStreamStart()
    {
        $this->write(
            '<?xml version="1.0" encoding="UTF-8"?><stream:stream'
            . ' from="'. $this->username . '@' . $this->domain . '"'
            . ' to="' . $this->domain
            . '" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" version="1.0">'
        );
    }

    /**
     * @Given Connection to xmpp server
     */
    public function connectionToXmppServer()
    {
        $this->connect($this->port1);
        $this->sendStreamStart();
    }

    /**
     * @Given Connection to second XMPP server
     */
    public function connectionToSecondXmppServer(): void
    {
        $this->connect($this->port2);
        $this->sendStreamStart();
    }

    /**
     * @Given Connection is encrypted by STARTTLS
     */
    public function connectionIsEncryptedByStarttls()
    {
        $this->write("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        $data = $this->readStreamUntil(array(
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        ));

        Assert::assertStringContainsString("<proceed", $data);

        $cryptoMethod = null;
        switch ($this->tlsversion) {
            case 'ssl':
            case 'tls':
                $cryptoMethod = STREAM_CRYPTO_METHOD_TLS_CLIENT;
                break;
            case 'tlsv1.0':
                $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT;
                break;
            case 'tlsv1.1':
                $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
                break;
            case 'tlsv1.2':
                $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
                break;
            case 'tlsv1.3':
                $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT; // available since PHP 7.4
                break;
        }

        Assert::assertTrue(stream_socket_enable_crypto($this->stream, true, $cryptoMethod));

        $this->sendStreamStart();
    }

    /**
     * @Given xmpp server supports authentication method :authenticationMethod
     */
    public function xmppServerSupportsAuthenticationMethod($authenticationMethod)
    {
        $data = $this->readStreamUntil('</stream:features>');
        Assert::assertStringContainsString("<mechanism>$authenticationMethod</mechanism>", $data);

        $mechanismsMatch = array();
        Assert::assertTrue((bool) preg_match_all(
            '#<mechanism>(?<mecha>[^<]+)</mechanism>#ms',
            $data,
            $mechanismsMatch
        ));
        $this->mechanisms = array_unique($mechanismsMatch['mecha']);

        $channelBindingMatch = array();
        if (preg_match_all("#<channel-binding type='(?<cb>[^']+)'#ms", $data, $channelBindingMatch)) {
            $this->channelBindings = array_unique($channelBindingMatch['cb']);
        }
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
     * @Given Downgrade protection is properly set up
     */
    public function downgradeProtectionIsProperlySetUp()
    {
        Assert::assertNotEmpty($this->mechanisms);
        Assert::assertNotEmpty($this->channelBindings);
    }

    /**
     * @Given We simulate downgrade protection error by adding an auth mechanism
     */
    public function weSimulateDowngradeProtectionErrorByAddingAnAuthMechanism()
    {
        $this->mechanisms[] = 'X-AUTH-FABIANG';
    }

    /**
     * @Given We simulate downgrade protection error by adding an unsupported channel-binding
     */
    public function weSimulateDowngradeProtectionErrorByAddingAnUnsupportedChannelBinding()
    {
        $this->channelBindings[] = 'tls-unsupported';
    }

    /**
     * @When authenticate with method DIGEST-MD5
     */
    public function authenticateWithMethodDigestMd5()
    {
        $this->write("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='DIGEST-MD5'/>");
    }

    /**
     * @When response to challenge received for DIGEST-MD5
     */
    public function responseToChallengeReceivedForDigestMd5()
    {
        $data = $this->readStreamUntil(array('</challenge>', '</failure>'));
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $authenticationObject = $this->authenticationFactory->factory('DIGEST-MD5', $this->getOptions());

        $challenge = substr($data, 52, -12);

        $response = $authenticationObject->createResponse(base64_decode($challenge));

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($response) . "</response>"
        );
    }

    /**
     * @When response to rspauth challenge
     */
    public function responseToRspauthChallenge()
    {
        $data = $this->readStreamUntil(array('</challenge>', '</failure>'));

        $challenge = base64_decode(substr($data, 52, -12));

        Assert::assertMatchesRegularExpression('/^rspauth=.+$/', $challenge);

        $this->write("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    }

    /**
     * @When response to challenge for SCRAM-SHA-:hash
     */
    public function responseToChallengeForScramSha($hash)
    {
        $data = $this->readStreamUntil(array('</challenge>', '</failure>'));
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $challenge = base64_decode(substr($data, 52, -12));

        $authData = $this->authenticationObject->createResponse($challenge);

        Assert::assertNotFalse($authData);

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($authData) . "</response>"
        );
    }

    /**
     * @When response to challenge for SCRAM-SHA-:hash was invalid
     */
    public function responseToChallengeForScramShaWasInvalid($hash)
    {
        $data = $this->readStreamUntil(array('</challenge>', '</failure>'));
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $challenge = base64_decode(substr($data, 52, -12));

        $authData = $this->authenticationObject->createResponse($challenge);

        Assert::assertFalse($authData);
        $this->write('</stream:stream>');
    }

    /**
     * @Then should be authenticated at xmpp server
     */
    public function shouldBeAuthenticatedAtXmppServer()
    {
        $data = $this->readStreamUntil(array(
            "</failure>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "</success>"
        ));

        Assert::assertSame("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", $data);
    }

    /**
     * @Then should be authenticated at xmpp server with verification
     */
    public function shouldBeAuthenticatedAtXmppServerWithVerification()
    {
        $data = $this->readStreamUntil(array(
            "</failure>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "</success>"
        ));
        Assert::assertMatchesRegularExpression(
            "#^<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</success>$#",
            $data
        );

        $verfication = base64_decode(substr($data, 50, -10));

        Assert::assertTrue($this->authenticationObject->verify($verfication));
    }

    /**
     * @Then Server connection should be closed
     */
    public function serverConnectionShouldBeClosed()
    {
        $this->readStreamUntil('</stream:stream>');
        stream_socket_shutdown($this->stream, STREAM_SHUT_RDWR);
        $this->stream = null;
    }

    /**
     * @AfterScenario
     */
    public function closeXMLStream()
    {
        if ($this->stream) {
            $this->write('</stream:stream>');
        }
    }
}
