<?php

use Porro\Core\Activity\AbuseIpdb;
use Porro\Core\Activity\Cloudflare;
use Porro\Core\Activity\FlaggedIp;
use Porro\Core\Activity\IpDetails;
use Porro\Core\Activity\ProtectedRanges;
use Porro\Core\Activity\Ranking;
use Porro\Core\Activity\Recorder;
use Porro\Core\Health\Sources;

/**
 * Sources answering the Tor and Spamhaus lists (and anything else in
 * $responses) from memory, counting requests.
 */
function listSources(array $responses = [], array &$calls = []): Sources
{
    $cache = [];
    $responses += [
        'GET '.IpDetails::TOR_URL => [200, "185.220.101.4\n171.25.193.25\n"],
        'GET '.IpDetails::DROP_URLS[0] => [200, "{\"cidr\":\"91.92.240.0/22\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"records\":1}\n"],
        'GET '.IpDetails::DROP_URLS[1] => [200, "{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL2\",\"rir\":\"ripencc\"}\n"],
    ];

    return new Sources(
        function (string $key) use (&$cache) {
            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value) use (&$cache) {
            $cache[$key] = $value;
        },
        function (string $method, string $url, array $headers) use (&$responses, &$calls) {
            $calls[] = [$method, $url, $headers];

            return $responses["{$method} {$url}"] ?? [0, ''];
        },
    );
}

function details(?Closure $network = null, ?Closure $dns = null, ?Sources $sources = null): IpDetails
{
    return new IpDetails($sources ?? listSources(), null, $network, $dns ?? fn () => null);
}

it('takes the network from Cloudflare and flags a hosting provider', function () {
    $d = details(fn () => ['country' => 'DE', 'asn' => 64500, 'network' => 'Example Hosting GmbH', 'network_type' => 'hosting_provider', 'risks' => ['Anonymizer'], 'source' => 'Cloudflare IP Intelligence'])
        ->lookup('185.220.101.4');

    expect($d)->toMatchArray(['country' => 'DE', 'asn' => 64500, 'network' => 'Example Hosting GmbH', 'risks' => ['Anonymizer']])
        ->and($d['badges'])->toBe([IpDetails::TOR, IpDetails::HOSTING])
        ->and($d['sources'])->toBe(['Cloudflare IP Intelligence', 'Tor exit list', 'Spamhaus DROP']);
});

it('matches Spamhaus DROP ranges, v4 and v6, and Cloudflare’s Tor country', function () {
    expect(details()->lookup('91.92.240.17')['badges'])->toBe([IpDetails::SPAMHAUS])
        ->and(details()->lookup('2001:678:254::9')['badges'])->toBe([IpDetails::SPAMHAUS])
        ->and(details(fn () => ['country' => 'T1', 'source' => 'Cloudflare'])->lookup('45.148.10.92')['badges'])->toBe([IpDetails::TOR])
        ->and(details()->lookup('45.148.10.92')['badges'])->toBe([]);
});

it('keeps working when Cloudflare and the lists can’t be reached', function () {
    $d = details(fn () => throw new RuntimeException('down'), null, listSources([
        'GET '.IpDetails::TOR_URL => [500, ''],
        'GET '.IpDetails::DROP_URLS[0] => [0, ''],
    ]))->lookup('185.220.101.4');

    expect($d['badges'])->toBe([])->and($d['network'])->toBeNull();
});

it('spots a fake Googlebot, and trusts a real one', function () {
    $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    expect(details()->lookup('45.148.10.92', $ua)['badges'])->toBe([IpDetails::FAKE_CRAWLER])
        ->and(details(dns: fn () => 'evil.example.net')->lookup('45.148.10.92', $ua)['badges'])->toBe([IpDetails::FAKE_CRAWLER]);

    $real = details(dns: fn () => 'crawl-66-249-66-1.googlebot.com')->lookup('66.249.66.1', $ua);

    expect($real['badges'])->toBe([])->and($real['crawler'])->toBe('googlebot')->and($real['hostname'])->toBe('crawl-66-249-66-1.googlebot.com');
});

it('recognises research scanners by their confirmed hostname', function () {
    expect(details(dns: fn () => 'scanner-12.ch1.censys-scanner.com')->lookup('167.94.138.5')['badges'])->toBe([IpDetails::SCANNER])
        ->and(details(dns: fn () => 'notcensys-scanner.com.evil.example')->lookup('167.94.138.5')['badges'])->toBe([]);
});

it('caches each IP for a day and the lists between lookups', function () {
    $calls = [];
    $network = 0;
    $lookup = new IpDetails(listSources([], $calls), null, function () use (&$network) {
        $network++;

        return ['country' => 'DE', 'source' => 'Cloudflare'];
    }, fn () => null);

    $lookup->lookup('185.220.101.4');
    $lookup->lookup('185.220.101.4');
    $lookup->lookup('45.148.10.92');

    expect($network)->toBe(2)->and($calls)->toHaveCount(3);
});

it('normalises the IP it looks up', function () {
    expect(details()->lookup('2001:0678:0254:0000::0009')['ip'])->toBe('2001:678:254::9')
        ->and(fn () => details()->lookup('not an ip'))->toThrow(InvalidArgumentException::class);
});

it('reads Cloudflare Intel and Radar', function () {
    $responses = [
        '/accounts/a1/intel/ip?ipv4=185.220.101.4' => ['belongs_to_ref' => ['value' => 64500, 'description' => 'Example Hosting GmbH', 'type' => 'hosting_provider', 'country' => 'DE'], 'risk_types' => [['id' => 1, 'name' => 'Anonymizer']]],
        '/radar/entities/ip?ip=185.220.101.4' => ['ip' => ['asn' => '64500', 'asnName' => 'EXAMPLE-AS', 'asnOrgName' => 'Example Hosting GmbH', 'location' => 'DE']],
    ];
    $cf = new Cloudflare('token', fn ($m, $url) => [200, json_encode(['success' => true, 'result' => $responses[substr($url, strlen(Cloudflare::API))] ?? null])], fn () => null);

    expect($cf->intel('a1', '185.220.101.4'))->toBe(['country' => 'DE', 'asn' => 64500, 'network' => 'Example Hosting GmbH', 'network_type' => 'hosting_provider', 'risks' => ['Anonymizer']])
        ->and($cf->radar('185.220.101.4'))->toBe(['country' => 'DE', 'asn' => 64500, 'network' => 'Example Hosting GmbH']);
});

it('checks AbuseIPDB only with a key, sending the key as a header', function () {
    $calls = [];
    $sources = listSources(['GET '.AbuseIpdb::URL.'?ipAddress=185.220.101.4&maxAgeInDays=90' => [200, json_encode(['data' => ['abuseConfidenceScore' => 100, 'totalReports' => 2048, 'lastReportedAt' => '2026-10-27T09:00:00+00:00', 'usageType' => 'Data Center/Web Hosting/Transit', 'isp' => 'Example Hosting']])]], $calls);

    expect((new AbuseIpdb($sources, ''))->check('185.220.101.4'))->toBeNull()
        ->and($calls)->toBe([])
        ->and((new AbuseIpdb($sources, 'k3y'))->check('185.220.101.4'))->toMatchArray(['score' => 100, 'reports' => 2048, 'isp' => 'Example Hosting'])
        ->and($calls[0][2]['Key'])->toBe('k3y');
});

it('remembers the last user agent of a flagged IP', function () {
    $cache = [];
    $recorder = new Recorder(
        function (string $key) use (&$cache) {
            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value) use (&$cache) {
            $cache[$key] = $value;
        },
        function (string $key) use (&$cache) {
            $cache[$key] = ($cache[$key] ?? 0) + 1;
        },
        new ProtectedRanges,
        'key',
    );

    foreach (['curl/8.0', 'Googlebot/2.1', str_repeat('x', 500)] as $ua) {
        $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, userAgent: $ua);
    }

    expect(strlen($recorder->summary()->flagged[0]->userAgent))->toBe(200)
        ->and($recorder->summary()->flagged[0]->toArray())->toHaveKey('user_agent');
});

describe('ranking', function () {
    function flaggedIp(string $ip, int $score, array $counts = [Recorder::PROBE => 1], int $lastSeen = 0): FlaggedIp
    {
        return new FlaggedIp($ip, $counts, 0, 'GET', '/', 404, $lastSeen, [], [], $score);
    }

    it('lifts IPs by what’s known about them, and sends scanners last', function () {
        $known = [
            '91.92.240.17' => ['badges' => [IpDetails::SPAMHAUS], 'risks' => [], 'network_type' => null],
            '185.220.101.4' => ['badges' => [IpDetails::TOR], 'risks' => ['Anonymizer'], 'network_type' => null],
            '45.148.10.92' => ['badges' => [IpDetails::HOSTING], 'risks' => [], 'network_type' => 'hosting_provider'],
            '167.94.138.5' => ['badges' => [IpDetails::SCANNER], 'risks' => [], 'network_type' => null],
        ];

        $ranked = Ranking::apply([
            flaggedIp('167.94.138.5', 500),
            flaggedIp('103.75.190.11', 40),
            // Equal once lifted: the one seen most recently goes first.
            flaggedIp('91.92.240.17', 15, lastSeen: 20),
            flaggedIp('185.220.101.4', 15, lastSeen: 30),
            flaggedIp('45.148.10.92', 30, [Recorder::LOGIN_FAILED => 10], lastSeen: 10),
        ], fn ($ip) => $known[$ip->ip] ?? ['badges' => [], 'risks' => [], 'network_type' => null]);

        expect(array_map(fn ($ip) => [$ip->ip, $ip->ranking()], $ranked))->toBe([
            ['185.220.101.4', 45.0],   // 15 × 1.5 Tor × 2 Anonymizer
            ['91.92.240.17', 45.0],    // 15 × 3 Spamhaus
            ['45.148.10.92', 45.0],    // 30 × 1.5 hosting trying passwords
            ['103.75.190.11', 40.0],
            ['167.94.138.5', 500.0],   // a research scanner: noisy, last
        ])
            ->and($ranked[0]->badges)->toBe([IpDetails::TOR, 'risk'])
            ->and($ranked[0]->toArray())->toMatchArray(['rank' => 45.0, 'badges' => [IpDetails::TOR, 'risk']]);
    });

    it('knows the lists without a lookup, and adds a cached lookup', function () {
        $calls = [];
        $sources = listSources([], $calls);
        $lookup = new IpDetails($sources, null, fn () => ['network_type' => 'hosting_provider', 'risks' => ['Botnet'], 'source' => 'Cloudflare'], fn () => 'scan.censys-scanner.com');

        expect($lookup->known('185.220.101.4'))->toBe(['badges' => [IpDetails::TOR], 'risks' => [], 'network_type' => null])
            ->and($lookup->known('91.92.240.1')['badges'])->toBe([IpDetails::SPAMHAUS]);

        $lookup->lookup('45.148.10.92');

        expect($lookup->known('45.148.10.92'))->toBe(['badges' => [IpDetails::HOSTING, IpDetails::SCANNER], 'risks' => ['Botnet'], 'network_type' => 'hosting_provider']);
    });
});
