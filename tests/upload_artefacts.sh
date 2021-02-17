#!/usr/bin/env bash
set +x

if [[ -n "$$TRAVIS_PHP_VERSION" && "$TRAVIS_PHP_VERSION" == "7.4" ]]; then
    wget https://scrutinizer-ci.com/ocular.phar
    wget https://github.com/php-coveralls/php-coveralls/releases/download/v2.4.3/php-coveralls.phar

    php ocular.phar code-coverage:upload --format=php-clover build/logs/clover.xml
    php php-coveralls.phar -x build/logs/clover.xml
fi
