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

use PHPUnit\Framework\Assert;
use Behat\Hook\BeforeScenario;
use Behat\Hook\AfterScenario;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;

/**
 * Defines application features from the specific context.
 *
 * @author f.grutschus
 */
abstract class AbstractContext
{
    protected string $hostname;
    protected int $port1;
    protected int $port2;
    protected string $username;
    protected string $password;

    protected string $logdir;
    protected $stream;
    protected $logfile;

    protected function connect(int $port): void
    {
        $errno  = null;
        $errstr = null;

        $connectionString = "tcp://{$this->hostname}:{$port}";

        $context = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'allow_self_signed' => true,
            ],
        ]);

        $this->stream = stream_socket_client($connectionString, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);

        Assert::assertNotFalse($this->stream, "Coudn't connection to host {$this->hostname}");
    }

    /**
     * Read stream until string is found.
     *
     * @throws \Exception
     */
    protected function readStreamUntil(string|array $until, int $timeout = 5): string
    {
        $readStart = time();

        if (is_string($until)) {
            $until = [$until];
        }

        $data = '';
        do {
            if (time() >= $readStart + $timeout) {
                throw new \Exception('Timeout when trying to receive buffer');
            }

            $data .= $this->read();

            foreach ($until as $cuntil) {
                $expected = strpos($data, $cuntil);

                if (false !== $expected) {
                    break 2;
                }
            }
        } while (1);

        return $data;
    }

    protected function read(): string
    {
        $data = fread($this->stream, 4096);
        if (strlen($data) > 0) {
            fwrite($this->logfile, 'S: ' . trim($data) . "\n");
        }
        return $data;
    }

    protected function write(string $data): void
    {
        fwrite($this->logfile, 'C: ' . trim($data) . "\n");
        fwrite($this->stream, $data);
    }

    #[BeforeScenario()]
    public function openLog(BeforeScenarioScope $scope): void
    {
        $featureTags  = $scope->getFeature()->getTags();
        $mechanism    = array_shift($featureTags);
        $scenarioTags = $scope->getScenario()->getTags();
        $type         = array_shift($scenarioTags);

        $this->logfile = fopen(
            sprintf(
                '%s/behat.%s.%s.%s.log',
                $this->logdir,
                $mechanism,
                $type,
                time()
            ),
            'c'
        );
    }

    #[AfterScenario()]
    public function closeConnection(): void
    {
        if ($this->stream) {
            fclose($this->stream);
            $this->stream = null;
        }

        fclose($this->logfile);
        $this->logfile = null;
    }
}
