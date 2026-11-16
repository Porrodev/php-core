<?php

namespace Porro\Core;

final class Result
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $status,
        public readonly bool $needLock = false,
        public readonly ?string $error = null,
        // Porro hasn't seen this npm lock file and wants its packages.
        public readonly bool $needNpmLock = false,
        // Porro hasn't seen this server's package list. Client::send()
        // sends it straight away, so connectors needn't act on it.
        public readonly bool $needSystemPackages = false,
    ) {}

    /**
     * Porro no longer accepts this site's key: the site was removed there,
     * given a new key, or disconnected. A clock that's out is a 401 too,
     * with its own message, and isn't this.
     */
    public function keyTurnedAway(): bool
    {
        return $this->status === 401 && $this->error === 'Invalid signature.';
    }
}
