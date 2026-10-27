<?php

namespace Porro\Core\Activity;

/**
 * One IP that crossed a threshold in the summary window.
 */
final class FlaggedIp
{
    /**
     * @param  array<string, int>  $counts  signal => count
     * @param  list<array{0: string, 1: string, 2: int, 3: int}>  $recent  [method, path, status, at], newest first
     * @param  array<string, int>  $hourly  "YmdH" => signals that hour
     */
    public function __construct(
        public readonly string $ip,
        public readonly array $counts,
        public readonly int $users,
        public readonly string $lastMethod,
        public readonly string $lastPath,
        public readonly int $lastStatus,
        public readonly int $lastSeen,
        public readonly array $recent,
        public readonly array $hourly,
        public readonly int $score,
        // Two-letter code from the edge (T1 is Cloudflare's Tor), or null.
        public readonly ?string $country = null,
    ) {}

    public function withCountry(?string $country): self
    {
        return new self($this->ip, $this->counts, $this->users, $this->lastMethod, $this->lastPath, $this->lastStatus, $this->lastSeen, $this->recent, $this->hourly, $this->score, $country);
    }

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

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'counts' => $this->counts,
            'users' => $this->users,
            'last_method' => $this->lastMethod,
            'last_path' => $this->lastPath,
            'last_status' => $this->lastStatus,
            'last_seen' => $this->lastSeen,
            'recent' => $this->recent,
            'hourly' => $this->hourly,
            'score' => $this->score,
            'country' => $this->country,
        ];
    }
}
