<?php

namespace Porro\Core;

final class Result
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $status,
        public readonly bool $needLock = false,
        public readonly ?string $error = null,
    ) {}
}
