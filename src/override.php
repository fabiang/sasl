<?php
// @codingStandardsIgnoreFile
// phpcs:ignore
// phpcs:disable
// @codeCoverageIgnoreStart

declare(strict_types=1);

if (!class_exists(Override::class)) {
    #[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
    final class Override
    {
        public function __construct()
        {
        }
    }
}
// @codeCoverageIgnoreEnd
