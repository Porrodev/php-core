<?php

namespace Porro\Core\Activity;

use RuntimeException;

/**
 * Cloudflare said no, or couldn't be reached. The message is written for
 * the person setting it up.
 */
final class CloudflareError extends RuntimeException
{
    public function __construct(string $message, public readonly int $status = 0, public readonly ?int $cloudflareCode = null)
    {
        parent::__construct($message);
    }
}
