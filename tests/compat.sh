#!/usr/bin/env bash

find tests/src/ -name "*Test.php" -print | xargs sed -i -E "s/protected function setUp\(\): void/protected function setUp()/"
