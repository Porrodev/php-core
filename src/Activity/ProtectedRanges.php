<?php

namespace Porro\Core\Activity;

use Porro\Core\Health\Sources;

/**
 * Addresses that must never be blocked or flagged: the CDN in front of
 * the site, the host's own servers and health checks, and private or
 * reserved ranges. Blocking any of them breaks the site or its deploys.
 *
 * Published lists are fetched daily. A response that isn't a clean list
 * of addresses (a sign-in page, an error) is thrown away whole, and the
 * copy bundled with this release is used instead, never an empty list.
 */
final class ProtectedRanges
{
    public const CLOUDFLARE = 'cloudflare';

    public const FORGE = 'forge';

    public const FORGE_HEALTH = 'forge_health';

    public const RESERVED = 'reserved';

    public const CONFIG = 'config';

    public const TTL = 86400;

    public const LABELS = [
        self::CLOUDFLARE => 'Cloudflare',
        self::FORGE => 'Laravel Forge',
        self::FORGE_HEALTH => 'Forge health checks',
        self::RESERVED => 'Private and reserved',
        self::CONFIG => 'This site’s config',
    ];

    /** Fetched daily. All of a source's URLs must parse, or its snapshot is used. */
    public const URLS = [
        self::CLOUDFLARE => ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'],
        // Forge publishes IPv4 only: ips-v6.txt redirects to its sign-in page.
        self::FORGE => ['https://forge.laravel.com/ips-v4.txt'],
    ];

    /** Bundled copies, checked 2026-10-27. Refresh at each release. */
    public const SNAPSHOT = [
        self::CLOUDFLARE => [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
            '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
            '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
            '2a06:98c0::/29', '2c0f:f248::/32',
        ],
        self::FORGE => ['159.203.150.232', '159.203.150.216', '45.55.124.124', '165.227.248.218', '142.93.78.212'],
        // Only listed on https://laravel.com/forge/docs/resources/network, so never fetched.
        self::FORGE_HEALTH => ['209.38.170.132', '206.189.255.228', '139.59.222.70'],
        self::RESERVED => [
            '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
            '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
            '224.0.0.0/4', '240.0.0.0/4',
            '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '100::/64', '2001:db8::/32', 'fc00::/7', 'fe80::/10', 'ff00::/8',
        ],
    ];

    /** @var array<string, list<Cidr>>|null */
    private ?array $ranges = null;

    private ?IpSet $set = null;

    /**
     * @param  list<string>  $extra  the site's own never-block ranges from config
     */
    public function __construct(
        private readonly ?Sources $sources = null,
        private readonly array $extra = [],
    ) {}

    /**
     * @return array<string, list<Cidr>>
     */
    public function ranges(): array
    {
        if ($this->ranges !== null) {
            return $this->ranges;
        }

        $lists = self::SNAPSHOT;

        foreach (self::URLS as $source => $urls) {
            $fetched = $this->sources?->remember("ranges:{$source}", self::TTL, function () use ($urls) {
                $all = [];

                foreach ($urls as $url) {
                    $list = self::parseList($this->sources->text('GET', $url) ?? '');

                    if ($list === null) {
                        return null;
                    }

                    array_push($all, ...$list);
                }

                return $all;
            });

            if (is_array($fetched) && $fetched !== []) {
                $lists[$source] = $fetched;
            }
        }

        $lists[self::CONFIG] = $this->extra;

        return $this->ranges = array_map(
            fn (array $list) => array_values(array_filter(array_map(Cidr::tryParse(...), $list))),
            $lists,
        );
    }

    /**
     * Which source protects $ip, or null.
     */
    public function match(string $ip): ?string
    {
        return $this->set()->match($ip);
    }

    /**
     * Which source shares any address with $cidr, or null.
     */
    public function overlapping(Cidr $cidr): ?string
    {
        return $this->set()->overlapping($cidr);
    }

    public function isCloudflare(string $ip): bool
    {
        foreach ($this->ranges()[self::CLOUDFLARE] as $range) {
            if ($range->contains($ip)) {
                return true;
            }
        }

        return false;
    }

    public static function label(string $source): string
    {
        return self::LABELS[$source] ?? $source;
    }

    /**
     * Every non-empty line as an address or range, or null when any line
     * isn't one or there are none: an HTML page is rejected, not half-used.
     *
     * @return list<string>|null
     */
    public static function parseList(string $body): ?array
    {
        $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $body) ?: []), fn ($line) => $line !== ''));

        if ($lines === []) {
            return null;
        }

        foreach ($lines as $line) {
            if (! Cidr::isValid($line)) {
                return null;
            }
        }

        return $lines;
    }

    private function set(): IpSet
    {
        if ($this->set === null) {
            $this->set = new IpSet;

            foreach ($this->ranges() as $source => $ranges) {
                foreach ($ranges as $range) {
                    $this->set->add($range, $source);
                }
            }
        }

        return $this->set;
    }
}
