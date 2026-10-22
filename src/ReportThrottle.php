<?php

namespace Porro\Core;

use Closure;

/**
 * Keeps backup reports (sent from the control panel when cron may be
 * missing) to one per interval, across every path that sends a report.
 *
 * The connector's cache holds when a report last went. Backup reports
 * claim the next slot with the cache's add(), which only one request can
 * win, so load-balanced servers sharing a cache send one report between
 * them. Cron, deploys and events always send and only reset the clock.
 */
final class ReportThrottle
{
    public const KEY = 'porro:report:sent';

    public const INTERVAL = 900;

    // Cron runs drift by a few seconds; this stops a backup report
    // slipping in just before cron's next one while cron is healthy.
    public const CRON_GRACE = 120;

    /**
     * @param  Closure(string $key, int $value, int $ttl): bool  $add  stores only when the key is missing; true when it did
     * @param  Closure(string $key, int $value, int $ttl): mixed  $set
     */
    public function __construct(
        private readonly Closure $add,
        private readonly Closure $set,
        private readonly int $interval = self::INTERVAL,
    ) {}

    /**
     * True when no report went in the last interval and this request won
     * the slot. The slot is taken either way, so a failed send waits too.
     */
    public function claim(): bool
    {
        return (bool) ($this->add)(self::KEY, time(), $this->interval);
    }

    /**
     * Records a report that went without asking, so backup reports wait.
     */
    public function sent(string $trigger): void
    {
        ($this->set)(self::KEY, time(), $this->interval + ($trigger === Report::TRIGGER_SCHEDULE ? self::CRON_GRACE : 0));
    }
}
