#!/usr/bin/env bash
set +x

if [[ -n "$UPLOAD_ARTIFACTS" && "$UPLOAD_ARTIFACTS" -eq 1 ]]; then
    wget https://scrutinizer-ci.com/ocular.phar
    php ocular.phar code-coverage:upload --format=php-clover build/logs/clover.xml
    php vendor/bin/coveralls
    php vendor/bin/test-reporter --stdout > codeclimate.json
    curl -X POST -d @codeclimate.json -H 'Content-Type: application/json' \
         -H 'User-Agent: Code Climate (PHP Test Reporter v0.1.1)' \
         https://codeclimate.com/test_reports
fi
