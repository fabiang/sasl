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
use Behat\Hook\AfterScenario;
use PHPUnit\Framework\Assert;
use Fabiang\SASL\SASL;
use Fabiang\SASL\Options;
use Fabiang\SASL\Options\DowngradeProtectionOptions;
use Fabiang\SASL\Authentication\AuthenticationInterface;

/**
 * Defines application features from the specific context.
 *
 * @author Fabian Grutschus <f.grutschus@lubyte.de>
 */
class XMPPContext extends AbstractContext implements Context, SnippetAcceptingContext
{
    private string $domain;
    private string $tlsversion;
    private AuthenticationInterface $mechanism;
    private array $mechanisms = [];
    private array $channelBindings = [];

    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     *
     * @param string  $hostname Hostname for connection
     * @param integer $port1
     * @param integer $port2
     * @param string  $domain
     * @param string  $username Domain name of server (important for connecting)
     * @param string  $password
     * @param string  $logdir
     * @param string  $tlsversion
     */
    public function __construct(
        string $hostname,
        string $port1,
        string $port2,
        string $domain,
        string $username,
        string $password,
        string $logdir,
        string $tlsversion = 'tlsv1.2'
    ) {
        $this->hostname = $hostname;
        $this->port1    = (int) $port1;
        $this->port2    = (int) $port2;
        $this->domain   = $domain;
        $this->username = $username;
        $this->password = $password;

        if (!is_dir($logdir)) {
            mkdir($logdir, 0777, true);
        }

        $this->logdir = $logdir;

        $this->tlsversion = $tlsversion;
    }

    private function getOptions(): Options
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

    #[Given('Connection to XMPP server')]
    public function connectionToXMPPServer(): void
    {
        $this->connect($this->port1);
        $this->sendStreamStart();
    }

    #[Given('Connection to second XMPP server')]
    public function connectionToSecondXMPPServer(): void
    {
        $this->connect($this->port2);
        $this->sendStreamStart();
    }

    #[Given('Connection is encrypted by STARTTLS')]
    public function connectionIsEncryptedByStarttls(): void
    {
        $this->write("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        $data = $this->readStreamUntil([
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        ]);

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

    #[Given('xmpp server supports authentication method :authenticationMethod')]
    public function xmppServerSupportsAuthenticationMethod(string $authenticationMethod): void
    {
        $data = $this->readStreamUntil('</stream:features>');
        Assert::assertStringContainsString("<mechanism>$authenticationMethod</mechanism>", $data);

        $mechanismsMatch = [];
        Assert::assertTrue((bool) preg_match_all(
            '#<mechanism>(?<mecha>[^<]+)</mechanism>#ms',
            $data,
            $mechanismsMatch
        ));
        $this->mechanisms = array_unique($mechanismsMatch['mecha']);

        $channelBindingMatch = [];
        if (preg_match_all("#<channel-binding type='(?<cb>[^']+)'#ms", $data, $channelBindingMatch)) {
            $this->channelBindings = array_unique($channelBindingMatch['cb']);
        }
    }

    #[Given('Downgrade protection is properly set up')]
    public function downgradeProtectionIsProperlySetUp(): void
    {
        Assert::assertNotEmpty($this->mechanisms);
        Assert::assertNotEmpty($this->channelBindings);
    }

    #[Given('We simulate downgrade protection error by adding an auth mechanism')]
    public function weSimulateDowngradeProtectionErrorByAddingAnAuthMechanism(): void
    {
        $this->mechanisms[] = 'X-AUTH-FABIANG';
    }

    #[Given('We simulate downgrade protection error by adding an unsupported channel-binding')]
    public function weSimulateDowngradeProtectionErrorByAddingAnUnsupportedChannelBinding(): void
    {
        $this->channelBindings[] = 'tls-unsupported';
    }

    #[When('authenticate with method PLAIN')]
    public function authenticateWithMethodPlain(): void
    {
        $this->mechanism = SASL::Plain->mechanism(new Options($this->username, $this->password));
        $authenticationData  = $this->mechanism->createResponse();
        $this->write(
            '<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">'
            . base64_encode($authenticationData) . '</auth>'
        );
    }

    #[When('authenticate with method SCRAM-SHA-1')]
    public function authenticateWithMethodScramSha1(): void
    {
        $this->mechanism = SASL::SCRAM_SHA_1->mechanism($this->getOptions());
        $authData = base64_encode($this->mechanism->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>$authData</auth>"
        );
    }

    #[When('authenticate with method SCRAM-SHA-256')]
    public function authenticateWithMethodScramSha256(): void
    {
        $this->mechanism = SASL::SCRAM_SHA_256->mechanism($this->getOptions());
        $authData = base64_encode($this->mechanism->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>$authData</auth>"
        );
    }

    #[When('authenticate with method SCRAM-SHA-512')]
    public function authenticateWithMethodScramSha512(): void
    {
        $this->mechanism = SASL::SCRAM_SHA_512->mechanism($this->getOptions());
        $authData = base64_encode($this->mechanism->createResponse());
        $this->write(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-512'>$authData</auth>"
        );
    }

    #[When('authenticate with method DIGEST-MD5')]
    public function authenticateWithMethodDigestMd5(): void
    {
        $this->mechanism = SASL::DigestMD5->mechanism($this->getOptions());
        $this->write("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='DIGEST-MD5'/>");
    }

    #[When('response to challenge received for DIGEST-MD5')]
    public function responseToChallengeReceivedForDigestMd5(): void
    {
        $data = $this->readStreamUntil(['</challenge>', '</failure>']);
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $challenge = substr($data, 52, -12);

        $response = $this->mechanism->createResponse(base64_decode($challenge));

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($response) . "</response>"
        );
    }

    #[When('response to rspauth challenge')]
    public function responseToRspauthChallenge(): void
    {
        $data = $this->readStreamUntil(['</challenge>', '</failure>']);

        $challenge = base64_decode(substr($data, 52, -12));

        Assert::assertMatchesRegularExpression('/^rspauth=.+$/', $challenge);

        $this->write("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    }

    #[When('response to challenge for SCRAM-SHA-:hash')]
    public function responseToChallengeForScramSha(string $hash): void
    {
        $data = $this->readStreamUntil(['</challenge>', '</failure>']);
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $challenge = base64_decode(substr($data, 52, -12));

        $authData = $this->mechanism->createResponse($challenge);

        Assert::assertNotFalse($authData);

        $this->write(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" . base64_encode($authData) . "</response>"
        );
    }

    #[When('response to challenge for SCRAM-SHA-:hash was invalid')]
    public function responseToChallengeForScramShaWasInvalid(string $hash): void
    {
        $data = $this->readStreamUntil(['</challenge>', '</failure>']);
        Assert::assertMatchesRegularExpression(
            "#<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</challenge>#",
            $data
        );

        $challenge = base64_decode(substr($data, 52, -12));

        $authData = $this->mechanism->createResponse($challenge);

        Assert::assertFalse($authData);
        $this->write('</stream:stream>');
    }

    #[Then('should be authenticated at xmpp server')]
    public function shouldBeAuthenticatedAtXmppServer(): void
    {
        $data = $this->readStreamUntil([
            "</failure>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "</success>"
        ]);

        Assert::assertSame("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", $data);
    }

    #[Then('should be authenticated at xmpp server with verification')]
    public function shouldBeAuthenticatedAtXmppServerWithVerification(): void
    {
        $data = $this->readStreamUntil([
            "</failure>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "</success>"
        ]);
        Assert::assertMatchesRegularExpression(
            "#^<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>[^<]+</success>$#",
            $data
        );

        $verfication = base64_decode(substr($data, 50, -10));

        Assert::assertTrue($this->mechanism->verify($verfication));
    }

    #[Then('Server connection should be closed')]
    public function serverConnectionShouldBeClosed(): void
    {
        $this->readStreamUntil('</stream:stream>');
        stream_socket_shutdown($this->stream, STREAM_SHUT_RDWR);
        $this->stream = null;
    }

    private function sendStreamStart(): void
    {
        $this->write(
            '<?xml version="1.0" encoding="UTF-8"?><stream:stream'
            . ' from="'. $this->username . '@' . $this->domain . '"'
            . ' to="' . $this->domain
            . '" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" version="1.0">'
        );
    }

    #[AfterScenario()]
    public function closeXMLStream(): void
    {
        if ($this->stream) {
            $this->write('</stream:stream>');
        }
    }
}
