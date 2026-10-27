<?php

namespace Porro\Core\Activity;

use Closure;
use Porro\Core\Health\Sources;
use Throwable;

/**
 * Who's behind an IP, for the details drawer, from sources that never
 * send the IP anywhere new:
 *
 *  - Cloudflare (Intel, else Radar) through $network, when the connector
 *    has Cloudflare set up: Cloudflare proxies this traffic already
 *  - DB-IP's country file, on the site
 *  - the Tor exit list and Spamhaus DROP, downloaded whole and checked here
 *  - reverse DNS, confirmed by a forward lookup, to tell a real Googlebot
 *    from a fake one and to spot research scanners
 *
 * Results are cached a day per IP. AbuseIPDB is separate: it only runs
 * when someone asks, because it does send the IP.
 */
final class IpDetails
{
    public const TTL = 86400;

    public const TOR_URL = 'https://check.torproject.org/torbulkexitlist';

    /** One JSON object per line; DROP now includes what was EDROP. */
    public const DROP_URLS = ['https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json'];

    public const TOR = 'tor';

    public const SPAMHAUS = 'spamhaus_drop';

    public const HOSTING = 'hosting';

    public const FAKE_CRAWLER = 'fake_crawler';

    public const SCANNER = 'scanner';

    /** Research scanners that say who they are in reverse DNS. */
    public const SCANNERS = [
        'censys-scanner.com', 'shodan.io', 'binaryedge.ninja', 'internet-measurement.com', 'stretchoid.com',
        'onyphe.net', 'criminalip.com', 'shadowserver.org', 'leakix.net', 'internet-census.org', 'alphastrike.io',
    ];

    /** Crawlers by user agent, and the domains a real one's reverse DNS ends in. */
    public const CRAWLERS = [
        'googlebot' => ['googlebot.com', 'google.com', 'googleusercontent.com'],
        'bingbot' => ['search.msn.com'],
        'applebot' => ['applebot.apple.com'],
        'yandexbot' => ['yandex.ru', 'yandex.net', 'yandex.com'],
    ];

    private readonly Closure $dns;

    /**
     * @param  (Closure(string $ip): ?array{country?: string|null, asn?: int|null, network?: string|null, network_type?: string|null, risks?: list<string>, source: string})|null  $network
     * @param  (Closure(string $ip): ?string)|null  $dns  the reverse DNS name, only when a forward lookup confirms it
     */
    public function __construct(
        private readonly Sources $sources,
        private readonly ?Countries $countries = null,
        private readonly ?Closure $network = null,
        ?Closure $dns = null,
    ) {
        $this->dns = $dns ?? self::confirmedHostname(...);
    }

    /**
     * @return array{ip: string, country: string|null, asn: int|null, network: string|null, network_type: string|null, hostname: string|null, badges: list<string>, risks: list<string>, crawler: string|null, sources: list<string>, fetched_at: int}
     */
    public function lookup(string $ip, ?string $userAgent = null): array
    {
        $ip = (string) Cidr::parse($ip);
        $crawler = self::claimedCrawler($userAgent);

        return $this->sources->remember('ipdetails:'.sha1($ip.'|'.$crawler), self::TTL, fn () => $this->fetch($ip, $crawler))
            ?? $this->fetch($ip, $crawler);
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(string $ip, ?string $crawler): array
    {
        $details = ['ip' => $ip, 'country' => null, 'asn' => null, 'network' => null, 'network_type' => null, 'hostname' => null, 'badges' => [], 'risks' => [], 'crawler' => $crawler, 'sources' => [], 'fetched_at' => time()];

        try {
            $network = $this->network ? ($this->network)($ip) : null;
        } catch (Throwable) {
            $network = null;
        }

        if (is_array($network)) {
            foreach (['country', 'asn', 'network', 'network_type'] as $key) {
                $details[$key] = $network[$key] ?? null;
            }

            $details['risks'] = array_values((array) ($network['risks'] ?? []));
            $details['sources'][] = (string) ($network['source'] ?? 'Cloudflare');
        }

        if ($details['country'] === null && $this->countries?->available()) {
            $details['country'] = $this->countries->lookup($ip);
            $details['sources'][] = 'DB-IP';
        }

        if ($details['country'] === 'T1' || $this->tor()->has($ip)) {
            $details['badges'][] = self::TOR;
        }

        if ($this->drop()->has($ip)) {
            $details['badges'][] = self::SPAMHAUS;
        }

        if ($details['network_type'] === 'hosting_provider') {
            $details['badges'][] = self::HOSTING;
        }

        try {
            $details['hostname'] = ($this->dns)($ip);
        } catch (Throwable) {
            $details['hostname'] = null;
        }

        if ($details['hostname'] !== null) {
            $details['sources'][] = 'reverse DNS';

            if (self::endsWithAny($details['hostname'], self::SCANNERS)) {
                $details['badges'][] = self::SCANNER;
            }
        }

        // Claims to be Googlebot, but its address doesn't belong to Google.
        if ($crawler !== null && ($details['hostname'] === null || ! self::endsWithAny($details['hostname'], self::CRAWLERS[$crawler]))) {
            $details['badges'][] = self::FAKE_CRAWLER;
        }

        $details['sources'] = array_values(array_unique([...$details['sources'], 'Tor exit list', 'Spamhaus DROP']));

        return $details;
    }

    /**
     * The crawler a user agent claims to be, or null.
     */
    public static function claimedCrawler(?string $userAgent): ?string
    {
        $userAgent = strtolower((string) $userAgent);

        foreach (array_keys(self::CRAWLERS) as $crawler) {
            if (str_contains($userAgent, $crawler)) {
                return $crawler;
            }
        }

        return null;
    }

    /**
     * Reverse DNS, kept only when the name resolves back to the same IP:
     * anyone can set their PTR record to "crawl.googlebot.com".
     */
    public static function confirmedHostname(string $ip): ?string
    {
        $name = @gethostbyaddr($ip);

        if (! is_string($name) || $name === '' || $name === $ip) {
            return null;
        }

        $v6 = str_contains($ip, ':');
        $records = @dns_get_record($name, $v6 ? DNS_AAAA : DNS_A) ?: [];
        $addresses = array_map(fn ($r) => (string) Cidr::tryParse((string) ($r[$v6 ? 'ipv6' : 'ip'] ?? '')), $records);

        return in_array((string) Cidr::parse($ip), $addresses, true) ? strtolower(rtrim($name, '.')) : null;
    }

    /**
     * Tor exits, refreshed hourly.
     */
    public function tor(): IpSet
    {
        $list = $this->sources->remember('list:tor', 3600, fn () => ProtectedRanges::parseList($this->sources->text('GET', self::TOR_URL) ?? ''));

        return IpSet::of(is_array($list) ? $list : []);
    }

    /**
     * Spamhaus DROP, refreshed daily.
     */
    public function drop(): IpSet
    {
        $list = $this->sources->remember('list:drop', 86400, function () {
            $ranges = [];

            foreach (self::DROP_URLS as $url) {
                $body = $this->sources->text('GET', $url);

                if ($body === null) {
                    return null;
                }

                foreach (preg_split('/\R/', $body) ?: [] as $line) {
                    $row = json_decode($line, true);

                    if (is_array($row) && is_string($row['cidr'] ?? null) && Cidr::isValid($row['cidr'])) {
                        $ranges[] = $row['cidr'];
                    }
                }
            }

            return $ranges === [] ? null : $ranges;
        });

        return IpSet::of(is_array($list) ? $list : []);
    }

    /**
     * @param  list<string>  $domains
     */
    private static function endsWithAny(string $hostname, array $domains): bool
    {
        foreach ($domains as $domain) {
            if ($hostname === $domain || str_ends_with($hostname, '.'.$domain)) {
                return true;
            }
        }

        return false;
    }
}
