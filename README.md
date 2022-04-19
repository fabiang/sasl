# fabiang/sasl

The PHP SASL Authentification Library.

[![Latest Stable Version](https://poser.pugx.org/fabiang/sasl/v/stable.svg)](https://packagist.org/packages/fabiang/sasl)
[![Total Downloads](https://poser.pugx.org/fabiang/sasl/downloads.svg)](https://packagist.org/packages/fabiang/sasl)
[![License](https://poser.pugx.org/fabiang/sasl/license.svg)](https://packagist.org/packages/fabiang/sasl)  
[![Unit Tests](https://github.com/fabiang/sasl/actions/workflows/unit.yml/badge.svg?branch=develop)](https://github.com/fabiang/sasl/actions/workflows/unit.yml)
[![Integration Tests](https://github.com/fabiang/sasl/actions/workflows/behat.yml/badge.svg?branch=develop)](https://github.com/fabiang/sasl/actions/workflows/behat.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fabiang/sasl/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/fabiang/sasl/?branch=develop)
[![Code Coverage](https://scrutinizer-ci.com/g/fabiang/sasl/badges/coverage.png?b=develop)](https://scrutinizer-ci.com/g/fabiang/sasl/?branch=develop)

Provides code to generate responses to common SASL mechanisms, including:
* Digest-MD5
* Cram-MD5
* Plain
* Anonymous
* Login (Pseudo mechanism)
* SCRAM

Full refactored version of the the original [Auth_SASL2 Pear package](http://pear.php.net/package/Auth_SASL2/).

## Installation

The easiest way to install fabiang/sasl is by using Composer:

```
curl -sS https://getcomposer.org/installer | php
php composer.phar require fabiang/sasl
```

## Usage

Use the factory method to create a authentication mechanism object:

```php
use Fabiang\Sasl\Sasl;

$factory = new Sasl;

$mechanism = $factory->factory('SCRAM-SHA-1', array(
    'authcid'  => 'username',
    'secret'   => 'password',
    'authzid'  => 'authzid', // optional. Username to proxy as
    'service'  => 'servicename', // optional. Name of the service
    'hostname' => 'hostname', // optional. Hostname of the service
));

$response = $mechanism->createResponse();
```

Challenge-based authentication mechanisms implement the interface
`Fabiang\Sasl\Authentication\ChallengeAuthenticationInterface`.
For those mechanisms call the method again with the challenge:

```php
$response = $mechanism->createResponse($challenge);
```

**Note**: The challenge must be Base64 decoded.

### SCRAM verification

To verify the data returned by the server for SCRAM you can call:

```php
$mechanism->verify($data);
```

If the method returns false you should disconnect.

### Required options

List of options required by authentication mechanisms.
For mechanisms that are challenge-based you'll need to call `createResponse()`
again and send the returned value to the server.

| Mechanism | Authcid | Secret | Authzid  | Service | Hostname | Challenge |
| --------- | ------- | ------ | -------- | ------- | -------- | --------- |
| Anonymous | yes     | no     | no       | no      | no       | no        |
| CramMD5   | yes     | yes    | no       | no      | no       | yes       |
| DigestMD5 | yes     | yes    | optional | yes     | yes      | yes       |
| External  | no      | no     | yes      | no      | no       | no        |
| Login     | yes     | yes    | no       | no      | no       | no        |
| Plain     | yes     | yes    | optional | no      | no       | no        |
| SCRAM-*   | yes     | yes    | optional | no      | no       | yes       |

## Unit tests

If you like this library and you want to contribute, make sure the unit tests
and integration tests are running. Composer will help you to install the right
version of PHPUnit and Behat.

```
composer install --dev
```

After that run the unit tests:

```
./vendor/bin/phpunit
```

## Integration tests

The integration tests verify the authentication methods against an Ejabberd and Dovecot server.

### Docker Compose

To launch the servers you can use the provided Docker Compose file.
Just [install Docker](https://www.docker.com/get-started/) and run:

```
docker-compose up -d
```

**Note:** ejabberd takes around *ten minutes* to start.

### Vagrant

To launch the servers you can use the provided Vagrant box.
Just [install Vagrant](https://www.vagrantup.com/downloads) and run:

```
vagrant up
```

After some minutes you'll have the runnig server instances inside of a virtual machine.

### RUN

Now you can run the integration tests:

```
./vendor/bin/behat -c tests/behat.yml.dist
```

## License

BSD-3-Clause. See the [LICENSE.md](LICENSE.md).
