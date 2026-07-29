<?php

declare(strict_types=1);

namespace SecretScan;

final class Finding
{
    public function __construct(
        public readonly string $file,
        public readonly int $line,
        public readonly string $rule,
        public readonly string $redacted
    ) {
    }
}
