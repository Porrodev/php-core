<?php

namespace Porro\Core;

/**
 * A finished connection: the key, now the site's, and what Porro calls
 * the site and the workspace it was added to.
 */
final class ConnectResult
{
    public function __construct(
        public readonly SiteKey $key,
        public readonly ?string $host = null,
        public readonly ?string $workspace = null,
    ) {}
}
