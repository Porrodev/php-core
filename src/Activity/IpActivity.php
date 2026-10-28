<?php

namespace Porro\Core\Activity;

/**
 * What one IP did on the site over the last hours, flagged or not: the
 * IP details page's summary. Built by Recorder::history().
 */
final class IpActivity
{
    /**
     * @param  array<string, int>  $counts  signal => count
     * @param  array<string, int>  $hourly  "YmdH" => requests that hour
     * @param  list<array{0: string, 1: string, 2: int, 3: int}>  $recent  [method, path, status, at], newest first
     * @param  array<string, array{0: int, 1: int}>  $paths  path => [requests, last status], most first
     * @param  array<string, int>  $categories  what its probes were after (Probes categories), most first
     * @param  array<string, int>  $agents  user agent => requests, most first
     * @param  array<string, int>  $hosts  host => requests, most first
     * @param  array<string, int>  $methods  GET, POST… => requests
     * @param  array<string, int>  $statuses  "2xx", "4xx"… => requests
     */
    public function __construct(
        public readonly string $ip,
        public readonly array $counts,
        // Every request recorded: signals, plus everything once it was flagged.
        public readonly int $requests,
        // Requests a block turned away before the app ran.
        public readonly int $turnedAway,
        public readonly int $firstSeen,
        public readonly int $lastSeen,
        public readonly bool $flagged,
        public readonly array $hourly,
        public readonly array $recent,
        public readonly array $paths,
        // Requests to paths past the ones listed.
        public readonly int $otherPaths,
        public readonly array $categories,
        public readonly array $agents,
        public readonly array $hosts,
        public readonly array $methods,
        public readonly array $statuses,
        // Requests that came through Cloudflare, and straight to the server.
        public readonly int $viaCloudflare,
        public readonly int $direct,
        public readonly ?string $country = null,
        // Past Recorder::FLOOD_AFTER requests an hour, counts are sampled.
        public readonly bool $estimated = false,
    ) {}

    /**
     * The signals it was seen for, biggest first, without zeros.
     *
     * @return array<string, int>
     */
    public function signals(): array
    {
        $signals = array_filter($this->counts);
        arsort($signals);

        return $signals;
    }
}
