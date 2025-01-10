# fabiang/sasl

The PHP SASL Authentification Library.
Full refactored version of the the original [Auth_SASL2 Pear package](http://pear.php.net/package/Auth_SASL2/).

Provides code to generate responses to common SASL mechanisms, including:

* Digest-MD5
* Cram-MD5
* Plain
* Anonymous
* Login (Pseudo mechanism)
* SCRAM

[![PHP Version Require](https://poser.pugx.org/fabiang/sasl/require/php)](https://packagist.org/packages/fabiang/sasl)
[![Latest Stable Version](https://poser.pugx.org/fabiang/sasl/v/stable.svg)](https://packagist.org/packages/fabiang/sasl)
[![Total Downloads](https://poser.pugx.org/fabiang/sasl/downloads.svg)](https://packagist.org/packages/fabiang/sasl)
[![License](https://poser.pugx.org/fabiang/sasl/license.svg)](https://packagist.org/packages/fabiang/sasl)
[![CI](https://github.com/fabiang/sasl/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/fabiang/sasl/actions/workflows/ci.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fabiang/sasl/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/fabiang/sasl/?branch=develop)
[![Code Coverage](https://scrutinizer-ci.com/g/fabiang/sasl/badges/coverage.png?b=develop)](https://scrutinizer-ci.com/g/fabiang/sasl/?branch=develop)

## Security

Please note that MD5- and SHA1-based authentication mechanism are considered insecure.
Therefore you should prefer at least SCRAM-SHA-256 for **non-secure connections (TLS)** when ever possible.
For that reason Digest-MD5, Cram-MD5 and SCRAM-SHA-1 are deprecated and were removed in modern server software.

## Installation

The easiest way to install fabiang/sasl is by using [Composer](https://getcomposer.org):

```
composer require fabiang/sasl
```

## Usage

Use the factory method to create a authentication mechanism object:

```php
use Fabiang\SASL\SASL;

$mechanism = SASL::SCRAM_SHA3_256->mechanism([
    'authcid'  => 'username',
    'secret'   => 'password',
    'authzid'  => 'authzid', // optional. Username to proxy as
    'service'  => 'servicename', // optional. Name of the service
    'hostname' => 'hostname', // optional. Hostname of the service
]);

$response = $mechanism->createResponse();
```

Or create from string:

```php
// throws Fabiang\SASL\Exception\UnsupportedMechanismException
$mechanism = SASL::fromString('SCRAM-SHA3-256')->mechanism([
    // ...
]);
```

Challenge-based authentication mechanisms implement the interface
`Fabiang\SASL\Authentication\ChallengeAuthenticationInterface`.
For those mechanisms call the method again with the challenge returned by the server:

```php
$response = $mechanism->createResponse($challenge);
```

**Note**: The challenge must be Base64 decoded.

### SCRAM verification

To verify the data returned by the server for SCRAM you can call:

```php
$trusted = $mechanism->verify($data);
```

If the method returns false you should disconnect.

### SCRAM downgrade protection

To enable [downgrade protection for SCRAM](https://xmpp.org/extensions/xep-0474.html), you'll need to pass
the allowed authentication mechanisms and channel-binding types via options to the factory:

**Note**: [Channel-binding](https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism#Channel_binding)
is currently not supported [due to limitations of PHP](https://github.com/php/php-src/issues/16766).

```php
$authentication = AuthenticationMechanism::SCRAM_SHA_1->mechanism([
    'authcid'  => 'username',
    'secret'   => 'password',
    'authzid'  => 'authzid', // optional. Username to proxy as
    'service'  => 'servicename', // optional. Name of the service
    'hostname' => 'hostname', // optional. Hostname of the service
    'downgrade_protection' => [ // optional. When `null` downgrade protection string from server won't be validated
        'allowed_mechanisms'       => ['SCRAM-SHA-1-PLUS', 'SCRAM-SHA-1'], // allowed mechanisms by the server
        'allowed_channel_bindings' => ['tls-unique', 'tls-exporter', 'tls-server-end-point'], // allowed channel-binding types by the server
    ],
]);
```

### Required options

List of options required by authentication mechanisms.
For mechanisms that are challenge-based you'll need to call `createResponse()`
again and send the returned value to the server.

| Mechanism  | Authcid  | Secret | Authzid  | Service | Hostname |     | Challenge |
| ---------- | -------- | ------ | -------- | ------- | -------- | --- | --------- |
| Anonymous  | optional | no     | no       | no      | no       |     | no        |
| Cram-MD5   | yes      | yes    | no       | no      | no       |     | yes       |
| Digest-MD5 | yes      | yes    | optional | yes     | yes      |     | yes       |
| External   | no       | no     | optional | no      | no       |     | no        |
| Login      | yes      | yes    | no       | no      | no       |     | no        |
| Plain      | yes      | yes    | optional | no      | no       |     | no        |
| SCRAM-*    | yes      | yes    | optional | no      | no       |     | yes       |

Authcid = e.g. username, Secret = e.g. password

## Unit tests

If you like this library and you want to contribute, make sure the unit tests
and integration tests are running.

Run the unit tests:

```
./vendor/bin/phpunit
```

## Integration tests

The integration tests verify the authentication methods against an Ejabberd and Dovecot server.

To launch the servers you can use the provided Docker Compose file.
Just [install Docker](https://www.docker.com/get-started/) and run:

```
docker compose up -d
```

**Note:** ejabberd takes up to *twenty minutes* to start.

Now you can run the integration tests:

```
./vendor/bin/behat
```

## License

BSD-3-Clause. See the [LICENSE.md](LICENSE.md).
