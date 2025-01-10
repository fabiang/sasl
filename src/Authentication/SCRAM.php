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
 * @author Jehan <jehan.marmottard@gmail.com>
 */

namespace Fabiang\SASL\Authentication;

use Fabiang\SASL\Authentication\AbstractAuthentication;
use Fabiang\SASL\Options;
use Fabiang\SASL\Exception\InvalidArgumentException;
use SensitiveParameterValue;
use Override;

/**
 * Implementation of SCRAM-* SASL mechanisms.
 * SCRAM mechanisms have 3 main steps (initial response, response to the server challenge, then server signature
 * verification) which keep state-awareness. Therefore a single class instanciation must be done
 * and reused for the whole authentication process.
 *
 * @author Jehan <jehan.marmottard@gmail.com>
 */
class SCRAM extends AbstractAuthentication implements ChallengeAuthenticationInterface, VerificationInterface
{
    private string $hashAlgo;
    private ?string $gs2Header = null;
    private ?string $cnonce = null;
    private ?string $firstMessageBare = null;
    private ?SensitiveParameterValue $saltedSecret = null;
    private ?string $authMessage = null;

    /**
     * Construct a SCRAM-H client where 'H' is a cryptographic hash function.
     *
     * @link http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xml "Hash Function
     * Textual Names" format of core PHP hash function.
     * @param Options $options
     * @param string  $hash The name cryptographic hash function 'H' as registered by IANA in the "Hash Function Textual
     * Names" registry.
     * @throws InvalidArgumentException
     */
    public function __construct(Options $options, string $hash)
    {
        parent::__construct($options);

        // Though I could be strict, I will actually also accept the naming used in the PHP core hash framework.
        // For instance "sha1" is accepted, while the registered hash name should be "SHA-1".
        $replaced = preg_replace('#^sha-(\d+)#i', 'sha\1', $hash);
        if ($replaced === null) {
            // @codeCoverageIgnoreStart
            throw new InvalidArgumentException("Could not normalize hash '$hash'");
            // @codeCoverageIgnoreEnd
        }
        $normalizedHash = strtolower($replaced);

        $hashAlgos = hash_algos();
        if (!in_array($normalizedHash, $hashAlgos)) {
            throw new InvalidArgumentException("Invalid SASL mechanism type '$hash'");
        }

        $this->hashAlgo = $normalizedHash;
    }

    /**
     * Provides the (main) client response for SCRAM-H.
     *
     * @param  string $challenge The challenge sent by the server.
     * If the challenge is null or an empty string, the result will be the "initial response".
     * @return string|false      The response (binary, NOT base64 encoded)
     */
    #[Override]
    public function createResponse(?string $challenge = null): string|false
    {
        $authcid = $this->options->getAuthcid();
        if ($authcid === null || $authcid === '') {
            return false;
        }

        $authcid = $this->formatName($authcid);

        $secret = $this->options->getSecret();
        if ($secret === null || $secret === '') {
            return false;
        }

        $authzid = $this->options->getAuthzid();
        if ($authzid !== null && $authzid !== '') {
            $authzid = $this->formatName($authzid);
        }

        if ($challenge === null) {
            return $this->generateInitialResponse($authcid, $authzid);
        } else {
            return $this->generateResponse($challenge, $secret);
        }
    }

    /**
     * Prepare a name for inclusion in a SCRAM response.
     *
     * @param string $username a name to be prepared.
     * @return string the reformated name.
     */
    private function formatName(string $username): string
    {
        return str_replace(['=', ','], ['=3D', '=2C'], $username);
    }

    /**
     * Generate the initial response which can be either sent directly in the first message or as a response to an empty
     * server challenge.
     *
     * @param string $authcid Prepared authentication identity.
     * @param string $authzid Prepared authorization identity.
     * @return string The SCRAM response to send.
     */
    private function generateInitialResponse(string $authcid, ?string $authzid): string
    {
        $gs2Header = 'n,';
        if ($authzid !== null && $authzid !== '') {
            $gs2Header .= 'a=' . $authzid;
        }
        $gs2Header .= ',';

        $this->gs2Header = $gs2Header;

        // I must generate a client nonce and "save" it for later comparison on second response.
        $this->cnonce = $this->generateCnonce();

        $this->firstMessageBare = 'n=' . $authcid . ',r=' . $this->cnonce;
        return $this->gs2Header . $this->firstMessageBare;
    }

    /**
     * Parses and verifies a non-empty SCRAM challenge.
     *
     * @param  string       $challenge The SCRAM challenge
     * @return string|false $secret The response to send; false in case of wrong challenge or if an initial response has
     * not been generated first.
     */
    private function generateResponse(
        string $challenge,
        #[\SensitiveParameter]
        string $secret
    ): string|false {
        /* @psalm-var array<int,string> $matches */
        $matches = [];

        $serverMessageRegexp = "#^r=(?<nonce>[\x21-\x2B\x2D-\x7E/]+)"
            . ",s=(?<salt>(?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9/+]{3}=|[A-Za-z0-9/+]{2}==)?)"
            . ",i=(?<iteration>[0-9]*)"
            . "(?<additionalAttr>(?:,[A-Za-z]=[^,]+)*)$#";

        if ($this->cnonce === null ||
            $this->gs2Header === null ||
            $this->firstMessageBare === null ||
            ! preg_match($serverMessageRegexp, $challenge, $matches)) {
            return false;
        }

        $additionalAttribute = $this->parseAdditionalAttributes($matches['additionalAttr']);

        if (isset($additionalAttribute['m'])) {
            return false;
        }

        $nonce = $matches['nonce'];
        $salt  = base64_decode($matches['salt']);

        if (! $salt) {
            // Invalid Base64.
            return false;
        }
        $i = intval($matches['iteration']);

        $cnonce = substr($nonce, 0, strlen($this->cnonce));
        if ($cnonce !== $this->cnonce) {
            // Invalid challenge! Are we under attack?
            return false;
        }

        if (! empty($additionalAttribute['h'])) {
            if (! $this->downgradeProtection($additionalAttribute['h'], "\x1f", "\x1e")) {
                return false;
            }
        }

        if (! empty($additionalAttribute['d'])) {
            if (! $this->downgradeProtection($additionalAttribute['d'], '|', ',')) {
                return false;
            }
        }

        $channelBinding       = 'c=' . base64_encode($this->gs2Header);
        $finalMessage         = $channelBinding . ',r=' . $nonce;
        $saltedSecret         = $this->hi($secret, $salt, $i);
        $this->saltedSecret   = new SensitiveParameterValue($saltedSecret);
        $clientKey            = $this->hmac($saltedSecret, "Client Key", true);
        $storedKey            = $this->hash($clientKey);
        $authMessage          = $this->firstMessageBare . ',' . $challenge . ',' . $finalMessage;
        $this->authMessage    = $authMessage;
        $clientSignature      = $this->hmac($storedKey, $authMessage, true);
        $clientProof          = $clientKey ^ $clientSignature;
        $proof                = ',p=' . base64_encode($clientProof);

        return $finalMessage . $proof;
    }

    private function downgradeProtection(
        string $expectedDowngradeProtectionHash,
        string $groupDelimiter,
        string $delimiter
    ): bool {
        if ($this->options->getDowngradeProtection() === null) {
            return true;
        }

        $actualDgPHash = base64_encode(
            $this->hash(
                $this->generateDowngradeProtectionVerification($groupDelimiter, $delimiter)
            )
        );
        return $expectedDowngradeProtectionHash === $actualDgPHash;
    }

    /**
     * Hi() call, which is essentially PBKDF2 (RFC-2898) with HMAC-H() as the pseudorandom function.
     *
     * @param string $str  The string to hash.
     * @param string $salt The salt value.
     * @param int $i The   iteration count.
     */
    private function hi(
        #[\SensitiveParameter]
        string $str,
        string $salt,
        int $i
    ): string {
        $int1   = "\0\0\0\1";
        $ui     = $this->hmac($str, $salt . $int1, true);
        $result = $ui;
        for ($k = 1; $k < $i; $k++) {
            $ui     = $this->hmac($str, $ui, true);
            $result = $result ^ $ui;
        }
        return $result;
    }

    /**
     * SCRAM has also a server verification step. On a successful outcome, it will send additional data which must
     * absolutely be checked against this function. If this fails, the entity which we are communicating with is
     * probably not the server as it has not access to your ServerKey.
     *
     * @param string $data The additional data sent along a successful outcome.
     * @return bool Whether the server has been authenticated.
     * If false, the client must close the connection and consider to be under a MITM attack.
     */
    #[Override]
    public function verify(string $data): bool
    {
        $verifierRegexp = '#^v=(?<verifier>(?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9/+]{3}=|[A-Za-z0-9/+]{2}==)?)'
            . '(?<additionalAttr>(?:,[A-Za-z]=[^,]+)*)$#';

        $matches = [];
        if (empty($this->saltedSecret) ||
            $this->authMessage === null ||
            ! preg_match($verifierRegexp, $data, $matches)) {
            // This cannot be an outcome, you never sent the challenge's response.
            return false;
        }

        $additionalAttribute = $this->parseAdditionalAttributes($matches['additionalAttr']);

        if (isset($additionalAttribute['m'])) {
            return false;
        }

        $saltedSecret = $this->saltedSecret->getValue();

        $verifier                = $matches['verifier'];
        $proposedServerSignature = base64_decode($verifier);
        $serverKey               = $this->hmac($saltedSecret, "Server Key", true);
        $serverSignature         = $this->hmac($serverKey, $this->authMessage, true);

        return $proposedServerSignature === $serverSignature;
    }

    private function parseAdditionalAttributes(string $addAttr): array
    {
        return array_column(
            array_map(
                fn($v) => explode('=', trim($v), 2),
                array_filter(explode(',', $addAttr))
            ),
            1,
            0
        );
    }

    private function hash(string $data): string
    {
        return hash($this->hashAlgo, $data, true);
    }

    private function hmac(string $key, string $str, bool $raw): string
    {
        return hash_hmac($this->hashAlgo, $str, $key, $raw);
    }

    public function getCnonce(): ?string
    {
        return $this->cnonce;
    }

    public function getSaltedSecret(): ?string
    {
        if ($this->saltedSecret === null) {
            return null;
        }

        return $this->saltedSecret->getValue();
    }

    public function getAuthMessage(): ?string
    {
        return $this->authMessage;
    }

    public function getHashAlgo(): string
    {
        return $this->hashAlgo;
    }
}
