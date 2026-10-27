<?php

namespace Porro\Core\Activity;

use Porro\Core\Health\Issue;

/**
 * What the recorder saw over a window, and the issues it raises.
 */
final class Summary
{
    /** Below this many signals the proxy check stays quiet. */
    public const PROXY_MIN = 20;

    public const PROXY_SHARE = 0.8;

    /** Turns a nginx answer to every dotfile except .well-known into a 404. */
    public const DOTFILE_FIX = 'location ~ /\.(?!well-known) { deny all; }';

    /** How each signal reads in a title, in order of how worrying it is. */
    private const PHRASES = [
        Recorder::PROBE => 'probing for secrets and admin tools',
        Recorder::LOGIN_FAILED => 'trying passwords',
        Recorder::POST_FLOOD => 'flooding forms',
        Recorder::NOT_FOUND => 'crawling for pages',
    ];

    /**
     * @param  array<string, int>  $totals  signal => count
     * @param  list<FlaggedIp>  $flagged  worst first
     * @param  list<array{path: string, ip: string, status: int, at: int}>  $exposed
     * @param  array<string, int>  $targets  username hash => IPs that tried it
     */
    public function __construct(
        public readonly int $hours,
        public readonly array $totals,
        public readonly array $flagged,
        public readonly float $proxiedShare,
        public readonly int $proxied,
        public readonly array $exposed,
        public readonly array $targets,
    ) {}

    /**
     * True when most signals came from a proxy or private address, so the
     * site can't see visitor IPs and blocking would hit the proxy.
     */
    public function cantSeeVisitors(): bool
    {
        return $this->proxied >= self::PROXY_MIN && $this->proxiedShare > self::PROXY_SHARE;
    }

    /**
     * @return list<Issue>
     */
    public function issues(): array
    {
        $issues = [];

        foreach ($this->exposed as $hit) {
            $issues[] = new Issue(
                'exposed_file',
                Issue::CRITICAL,
                "{$hit['path']} is publicly readable",
                "Returned {$hit['status']} to {$hit['ip']} at ".gmdate('H:i', $hit['at']).' UTC · anyone can read it, so rotate anything it holds once it’s blocked',
                self::DOTFILE_FIX,
            );
        }

        if ($this->cantSeeVisitors()) {
            $issues[] = new Issue(
                'client_ip_unknown',
                Issue::WARNING,
                'Can’t see visitor IPs',
                'Most requests seem to come from a proxy or private address. Set the site’s trusted proxies so it sees the real visitor; until then blocking is off, as it would block the proxy.',
            );
        }

        if ($this->flagged !== []) {
            $issues[] = new Issue('suspicious_activity', Issue::WARNING, $this->title(), $this->detail());
        }

        return $issues;
    }

    /**
     * "3 IPs probing for secrets and admin tools"
     */
    public function title(): string
    {
        $by = $this->bySignal();
        $count = count($this->flagged);
        $ips = $count === 1 ? '1 IP' : "{$count} IPs";

        foreach (self::PHRASES as $signal => $phrase) {
            if (($by[$signal] ?? 0) > 0) {
                return "{$ips} {$phrase}";
            }
        }

        return "{$ips} look suspicious";
    }

    public function detail(): string
    {
        $parts = [];

        foreach (self::PHRASES as $signal => $phrase) {
            if (($by = $this->bySignal()[$signal] ?? 0) > 0) {
                $parts[] = ($by === 1 ? '1 IP ' : "{$by} IPs ").$phrase;
            }
        }

        return implode(' · ', $parts).' · in the last '.$this->hours.' hours';
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'hours' => $this->hours,
            'totals' => $this->totals,
            'flagged' => array_map(fn (FlaggedIp $ip) => $ip->toArray(), $this->flagged),
            'proxied_share' => $this->proxiedShare,
            'exposed' => $this->exposed,
            'targets' => $this->targets,
        ];
    }

    /**
     * How many flagged IPs showed each signal.
     *
     * @return array<string, int>
     */
    private function bySignal(): array
    {
        $by = [];

        foreach ($this->flagged as $ip) {
            foreach (array_keys($ip->signals()) as $signal) {
                $by[$signal] = ($by[$signal] ?? 0) + 1;
            }
        }

        return $by;
    }
}
