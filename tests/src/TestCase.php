<?php

namespace Fabiang\Sasl;

use PHPUnit\Framework\TestCase as BaseTestCase;
use PHPUnit\Framework\Assert;

abstract class TestCase extends BaseTestCase
{
    public static function assertMatchesRegularExpressionCompat(
        $pattern,
        $string,
        $message = ''
    ) {
        if (! method_exists('PHPUnit\Framework\Assert', 'assertMatchesRegularExpression')) {
            parent::assertRegExp($pattern, $string, $message);
            return;
        }

        parent::assertMatchesRegularExpression($pattern, $string, $message);
    }
}
