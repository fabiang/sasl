<?php
// @codingStandardsIgnoreFile
// phpcs:ignore
// @codeCoverageIgnoreStart

declare(strict_types=1);

if (!class_exists(Deprecated::class)) {

    #[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
    final class Deprecated
    {
        public readonly ?string $message;
        public readonly ?string $since;

        public function __construct(?string $message = null, ?string $since = null)
        {
            $this->message = $message;
            $this->since   = $since;
        }
    }

}
// @codeCoverageIgnoreEnd
