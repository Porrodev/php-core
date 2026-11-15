<?php

namespace Porro\Core;

/**
 * A request to connect that Porro has accepted and someone now has to
 * approve: its id, and the page on Porro to send their browser to.
 */
final class ConnectRequest
{
    public function __construct(
        public readonly string $id,
        public readonly string $approveUrl,
        // ISO 8601, as Porro sent it. About ten minutes from now.
        public readonly ?string $expiresAt = null,
    ) {}
}
