<?php

use Porro\Core\Activity\Blocklist;
use Porro\Core\Activity\Cidr;
use Porro\Core\Activity\ClientIp;
use Porro\Core\Activity\Countries;
use Porro\Core\Activity\Entry;
use Porro\Core\Activity\EntryStore;
use Porro\Core\Activity\FlaggedIp;
use Porro\Core\Activity\IpSet;
use Porro\Core\Activity\NginxBlocklist;
use Porro\Core\Activity\NginxStatus;
use Porro\Core\Activity\Probes;
use Porro\Core\Activity\ProtectedRanges;
use Porro\Core\Activity\Recorder;
use Porro\Core\Activity\Refused;
use Porro\Core\Health\Issue;
use Porro\Core\Health\Sources;

/**
 * An in-memory EntryStore, like a connector's database table.
 */
function memoryStore(array $entries = []): EntryStore
{
    return new class($entries) implements EntryStore
    {
        /** @param list<Entry> $entries */
        public function __construct(public array $entries) {}

        public function all(): array
        {
            return array_values($this->entries);
        }

        public function put(Entry $entry): void
        {
            $this->entries = array_values(array_filter($this->entries, fn (Entry $e) => $e->cidr !== $entry->cidr));
            $this->entries[] = $entry;
        }

        public function remove(string $cidr): void
        {
            $this->entries = array_values(array_filter($this->entries, fn (Entry $e) => $e->cidr !== $cidr));
        }
    };
}

/**
 * A Recorder over an array cache.
 *
 * @param  array<string, mixed>  $cache
 */
function recorder(?array &$cache = null, ?Closure $safelisted = null, array $thresholds = []): Recorder
{
    $cache ??= [];

    return new Recorder(
        function (string $key) use (&$cache) {
            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value, int $ttl) use (&$cache) {
            $cache[$key] = $value;
        },
        function (string $key, int $ttl) use (&$cache) {
            $cache[$key] = ($cache[$key] ?? 0) + 1;
        },
        new ProtectedRanges,
        'app-key',
        $safelisted,
        $thresholds,
    );
}

// 2026-10-27 09:00:00 UTC
const ACTIVITY_NOW = 1793091600;

describe('cidr', function () {
    it('normalises addresses and ranges', function (string $in, string $out) {
        expect((string) Cidr::parse($in))->toBe($out);
    })->with([
        ['203.0.113.7', '203.0.113.7'],
        ['203.0.113.7/24', '203.0.113.0/24'],
        [' 2001:DB8::1 ', '2001:db8::1'],
        ['2001:db8:abcd:12::1/48', '2001:db8:abcd::/48'],
        ['10.0.0.1/32', '10.0.0.1'],
    ]);

    it('rejects anything that isn’t an address or range', function (string $in) {
        expect(Cidr::tryParse($in))->toBeNull();
    })->with(['', 'example.com', '300.1.1.1', '10.0.0.0/33', '::1/129', '10.0.0.0/x', '<html>']);

    it('knows what it contains', function () {
        $range = Cidr::parse('203.0.113.0/24');

        expect($range->contains('203.0.113.250'))->toBeTrue()
            ->and($range->contains('203.0.114.1'))->toBeFalse()
            ->and($range->contains('2001:db8::1'))->toBeFalse()
            ->and($range->contains(Cidr::parse('203.0.113.128/25')))->toBeTrue()
            ->and($range->contains(Cidr::parse('203.0.0.0/16')))->toBeFalse()
            ->and(Cidr::parse('2001:db8::/32')->contains('2001:db8:ffff::1'))->toBeTrue();
    });

    it('knows when two ranges overlap', function () {
        expect(Cidr::parse('203.0.0.0/16')->overlaps(Cidr::parse('203.0.113.7')))->toBeTrue()
            ->and(Cidr::parse('203.0.113.7')->overlaps(Cidr::parse('203.0.0.0/16')))->toBeTrue()
            ->and(Cidr::parse('203.0.113.0/24')->overlaps(Cidr::parse('203.0.114.0/24')))->toBeFalse();
    });

    it('counts the addresses it covers', function () {
        expect(Cidr::parse('203.0.113.0/24')->size())->toBe(256)
            ->and(Cidr::parse('10.0.0.0/8')->size())->toBe(16_777_216)
            ->and(Cidr::parse('2001:db8::/32')->size())->toBe(PHP_INT_MAX);
    });
});

describe('ip set', function () {
    it('matches exact addresses and ranges, v4 and v6', function () {
        $set = IpSet::of(['185.220.101.4' => 'scanner', '103.75.190.0/24' => 'network', '2a03:b0c0::/32' => 'v6']);

        expect($set->match('185.220.101.4'))->toBe('scanner')
            ->and($set->match('103.75.190.200'))->toBe('network')
            ->and($set->match('2a03:b0c0:3:d0::1a2:f001'))->toBe('v6')
            ->and($set->match('185.220.101.5'))->toBeNull()
            ->and($set->match('not an ip'))->toBeNull()
            ->and($set->count())->toBe(3);
    });

    it('finds entries overlapping a range', function () {
        $set = IpSet::of(['185.220.101.4' => 'one']);

        expect($set->overlapping(Cidr::parse('185.220.101.0/24')))->toBe('one')
            ->and($set->overlapping(Cidr::parse('185.220.102.0/24')))->toBeNull();
    });
});

describe('protected ranges', function () {
    it('uses the bundled lists without a network', function () {
        $ranges = new ProtectedRanges;

        expect($ranges->match('104.16.1.1'))->toBe(ProtectedRanges::CLOUDFLARE)
            ->and($ranges->match('2606:4700::1'))->toBe(ProtectedRanges::CLOUDFLARE)
            ->and($ranges->match('159.203.150.232'))->toBe(ProtectedRanges::FORGE)
            ->and($ranges->match('209.38.170.132'))->toBe(ProtectedRanges::FORGE_HEALTH)
            ->and($ranges->match('192.168.1.10'))->toBe(ProtectedRanges::RESERVED)
            ->and($ranges->match('::1'))->toBe(ProtectedRanges::RESERVED)
            ->and($ranges->match('185.220.101.4'))->toBeNull();
    });

    it('uses fetched lists when every URL parses', function () {
        $sources = activitySources([
            'GET https://www.cloudflare.com/ips-v4' => [200, "173.245.48.0/20\n"],
            'GET https://www.cloudflare.com/ips-v6' => [200, "2400:cb00::/32\n"],
            'GET https://forge.laravel.com/ips-v4.txt' => [200, "45.55.124.124\n8.8.4.4\n"],
        ]);

        $ranges = new ProtectedRanges($sources);

        expect($ranges->match('8.8.4.4'))->toBe(ProtectedRanges::FORGE)
            ->and($ranges->isCloudflare('104.16.1.1'))->toBeFalse()
            ->and($ranges->isCloudflare('173.245.48.1'))->toBeTrue();
    });

    it('throws away a response that isn’t a clean list, keeping the snapshot', function () {
        $sources = activitySources([
            'GET https://www.cloudflare.com/ips-v4' => [200, "173.245.48.0/20\n"],
            // Like forge.laravel.com/ips-v6.txt: a sign-in page with a 200.
            'GET https://www.cloudflare.com/ips-v6' => [200, '<!DOCTYPE html><html><body>Sign in</body></html>'],
            'GET https://forge.laravel.com/ips-v4.txt' => [500, ''],
        ]);

        $ranges = new ProtectedRanges($sources);

        expect($ranges->isCloudflare('104.16.1.1'))->toBeTrue()
            ->and($ranges->match('159.203.150.232'))->toBe(ProtectedRanges::FORGE);
    });

    it('parses lists strictly', function () {
        expect(ProtectedRanges::parseList("1.2.3.4\r\n\n5.6.7.0/24\n"))->toBe(['1.2.3.4', '5.6.7.0/24'])
            ->and(ProtectedRanges::parseList(''))->toBeNull()
            ->and(ProtectedRanges::parseList("1.2.3.4\n<html>"))->toBeNull();
    });

    it('protects Google’s and Bing’s verified crawlers, from the bundled lists or fetched ones', function () {
        $ranges = new ProtectedRanges;

        expect($ranges->match('66.249.66.1'))->toBe(ProtectedRanges::CRAWLERS)
            ->and($ranges->match('157.55.39.10'))->toBe(ProtectedRanges::CRAWLERS)
            // Google Cloud is rentable by anyone: not protected.
            ->and($ranges->match('34.120.0.1'))->toBeNull();

        $google = json_encode(['creationTime' => 'x', 'prefixes' => [['ipv4Prefix' => '66.249.64.0/27'], ['ipv6Prefix' => '2001:4860:4801:10::/64']]]);
        $bing = json_encode(['prefixes' => [['ipv4Prefix' => '157.55.39.0/24']]]);
        $fetched = new ProtectedRanges(activitySources([
            'GET '.ProtectedRanges::JSON_URLS[ProtectedRanges::CRAWLERS][0] => [200, $google],
            'GET '.ProtectedRanges::JSON_URLS[ProtectedRanges::CRAWLERS][1] => [200, $bing],
        ]));

        expect($fetched->match('66.249.64.10'))->toBe(ProtectedRanges::CRAWLERS)
            ->and($fetched->match('66.249.66.1'))->toBeNull()
            ->and($fetched->match('2001:4860:4801:10::5'))->toBe(ProtectedRanges::CRAWLERS);

        expect(fn () => (new Blocklist(memoryStore(), memoryStore(), $ranges))->block('66.249.66.1', 'x'))->toThrow(Refused::class);
    });

    it('keeps the bundled crawlers when a list changes shape or can’t be fetched', function () {
        $ranges = new ProtectedRanges(activitySources([
            'GET '.ProtectedRanges::JSON_URLS[ProtectedRanges::CRAWLERS][0] => [200, '{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"not an ip"}]}'],
            'GET '.ProtectedRanges::JSON_URLS[ProtectedRanges::CRAWLERS][1] => [500, ''],
        ]));

        expect($ranges->match('66.249.66.1'))->toBe(ProtectedRanges::CRAWLERS)
            ->and(ProtectedRanges::parsePrefixes('<html>'))->toBeNull()
            ->and(ProtectedRanges::parsePrefixes('{"prefixes":[]}'))->toBeNull()
            ->and(ProtectedRanges::parsePrefixes('{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}'))->toBe(['1.2.3.0/24', '2001:db8::/32']);
    });

    it('lets a site switch off Forge and the crawlers, but never Cloudflare or private ranges', function () {
        $ranges = new ProtectedRanges(null, [], [ProtectedRanges::CRAWLERS, ProtectedRanges::FORGE, ProtectedRanges::CLOUDFLARE, ProtectedRanges::RESERVED]);

        expect($ranges->match('66.249.66.1'))->toBeNull()
            ->and($ranges->match('159.203.150.232'))->toBeNull()
            ->and($ranges->match('104.16.1.1'))->toBe(ProtectedRanges::CLOUDFLARE)
            ->and($ranges->match('10.0.0.1'))->toBe(ProtectedRanges::RESERVED)
            ->and($ranges->off())->toBe([ProtectedRanges::CRAWLERS, ProtectedRanges::FORGE]);
    });

    it('explains every list, with its source and whether it can be switched off', function () {
        $about = array_column((new ProtectedRanges(null, ['81.2.69.0/24'], [ProtectedRanges::FORGE]))->about(), null, 'source');

        expect(array_keys($about))->toBe(array_keys(ProtectedRanges::LABELS))
            ->and($about[ProtectedRanges::CRAWLERS]['why'])->toContain('drop the site from search')
            ->and($about[ProtectedRanges::CRAWLERS]['from'])->toHaveCount(2)
            ->and($about[ProtectedRanges::RESERVED])->toMatchArray(['optional' => false, 'on' => true])
            ->and($about[ProtectedRanges::FORGE])->toMatchArray(['optional' => true, 'on' => false, 'ranges' => []])
            ->and($about[ProtectedRanges::CONFIG]['ranges'])->toBe(['81.2.69.0/24']);
    });

    it('adds the site’s own ranges from config', function () {
        expect((new ProtectedRanges(null, ['81.2.69.0/24']))->match('81.2.69.142'))->toBe(ProtectedRanges::CONFIG);
    });
});

describe('client ip', function () {
    it('believes CF-Connecting-IP only from Cloudflare', function () {
        $ranges = new ProtectedRanges;

        expect(ClientIp::resolve('104.16.1.1', ['CF-Connecting-IP' => '185.220.101.4'], $ranges))->toBe('185.220.101.4')
            ->and(ClientIp::resolve('104.16.1.1', ['cf-connecting-ip' => ['185.220.101.4']], $ranges))->toBe('185.220.101.4')
            ->and(ClientIp::resolve('45.148.10.92', ['CF-Connecting-IP' => '1.1.1.1'], $ranges))->toBe('45.148.10.92')
            ->and(ClientIp::resolve('104.16.1.1', ['CF-Connecting-IP' => 'nonsense'], $ranges))->toBe('104.16.1.1')
            ->and(ClientIp::resolve('104.16.1.1', [], $ranges))->toBe('104.16.1.1');
    });
});

describe('probes', function () {
    it('names the category of scanner paths', function (string $path, ?string $category) {
        expect((new Probes)->match($path))->toBe($category);
    })->with([
        ['/.env', Probes::SECRETS],
        ['/.env.production', Probes::SECRETS],
        ['/%2Eenv?x=1', Probes::SECRETS],
        ['//.ENV', Probes::SECRETS],
        ['/backup.zip', Probes::SECRETS],
        ['/db/dump.sql.gz', Probes::SECRETS],
        ['/wp-config.php.bak', Probes::SECRETS],
        ['/.aws/credentials', Probes::SECRETS],
        ['/.git/config', Probes::VCS],
        ['/.svn/entries', Probes::VCS],
        ['/wp-login.php', Probes::WORDPRESS],
        ['/blog/xmlrpc.php', Probes::WORDPRESS],
        ['/wp-admin/', Probes::WORDPRESS],
        ['/phpmyadmin/', Probes::DB_ADMIN],
        ['/adminer.php', Probes::DB_ADMIN],
        ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', Probes::EXPLOIT],
        ['/_ignition/execute-solution', Probes::EXPLOIT],
        ['/cgi-bin/luci', Probes::EXPLOIT],
        ['/', null],
        ['/environment', null],
        ['/blog/git-tips', null],
        ['/about.sql-guide', null],
        ['/.well-known/acme-challenge/x', null],
        ['/admin/login', null],
        ['/pmanagement', null],
        ['/pma/', Probes::DB_ADMIN],
    ]);

    it('leaves paths the app really serves alone', function () {
        $probes = new Probes('laravel', ['/telescope']);

        expect($probes->match('/telescope/requests'))->toBeNull()
            ->and((new Probes)->match('/telescope/requests'))->toBe(Probes::EXPLOIT);
    });

    it('skips WordPress paths on WordPress', function () {
        expect((new Probes('wordpress'))->match('/wp-login.php'))->toBeNull();
    });

    it('knows which categories expose a file', function () {
        expect(Probes::exposes(Probes::SECRETS))->toBeTrue()
            ->and(Probes::exposes(Probes::VCS))->toBeTrue()
            ->and(Probes::exposes(Probes::WORDPRESS))->toBeFalse()
            ->and(Probes::exposes(null))->toBeFalse();
    });
});

describe('recorder', function () {
    it('flags an IP after three probes in an hour', function () {
        $recorder = recorder($cache);

        foreach (['/.env', '/.git/config', '/backup.zip'] as $i => $path) {
            $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', $path, 404, at: ACTIVITY_NOW + $i);
        }

        $summary = $recorder->summary(24, ACTIVITY_NOW + 60);
        $ip = $summary->flagged[0];

        expect($summary->totals[Recorder::PROBE])->toBe(3)
            ->and($ip->ip)->toBe('185.220.101.4')
            ->and($ip->counts[Recorder::PROBE])->toBe(3)
            ->and($ip->lastPath)->toBe('/backup.zip')
            ->and($ip->recent[0])->toBe(['GET', '/backup.zip', 404, ACTIVITY_NOW + 2])
            ->and($ip->score)->toBe(15);
    });

    it('doesn’t flag below the thresholds but still counts', function () {
        $recorder = recorder($cache);
        $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW);
        $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + 1);

        $summary = $recorder->summary(24, ACTIVITY_NOW + 60);

        expect($summary->flagged)->toBe([])
            ->and($summary->totals[Recorder::PROBE])->toBe(2)
            ->and($summary->issues())->toBe([]);
    });

    it('flags 404 and form bursts within ten minutes, not spread over an hour', function () {
        $recorder = recorder($cache, thresholds: [Recorder::NOT_FOUND => 5]);

        // Five 404s, one every 12 minutes: never five in one 10-minute slot.
        for ($i = 0; $i < 5; $i++) {
            $recorder->record('45.148.10.92', Recorder::NOT_FOUND, 'GET', "/page-{$i}", 404, at: ACTIVITY_NOW + $i * 720);
        }

        // Five in two minutes.
        for ($i = 0; $i < 5; $i++) {
            $recorder->record('103.75.190.11', Recorder::NOT_FOUND, 'GET', "/x-{$i}", 404, at: ACTIVITY_NOW + $i * 20);
        }

        $flagged = array_map(fn ($ip) => $ip->ip, $recorder->summary(24, ACTIVITY_NOW + 3600)->flagged);

        expect($flagged)->toBe(['103.75.190.11']);
    });

    it('flags password spraying by distinct usernames, kept only as hashes', function () {
        $recorder = recorder($cache);

        foreach (['a@x.test', 'b@x.test', 'c@x.test', 'd@x.test', 'admin@dogearbooks.example'] as $i => $user) {
            $recorder->record('194.26.29.113', Recorder::LOGIN_FAILED, 'POST', '/admin/login', 302, $user, ACTIVITY_NOW + $i);
        }

        $summary = $recorder->summary(24, ACTIVITY_NOW + 60);

        expect($summary->flagged[0]->users)->toBe(5)
            ->and($summary->targets)->toHaveKey($recorder->userHash('Admin@DogEarBooks.example'))
            ->and(json_encode($cache))->not->toContain('dogearbooks');
    });

    it('counts how many IPs targeted the same account', function () {
        $recorder = recorder($cache);

        foreach (['45.148.10.92', '194.26.29.113', '103.75.190.11'] as $ip) {
            $recorder->record($ip, Recorder::LOGIN_FAILED, 'POST', '/admin/login', 302, 'admin@dogearbooks.example', ACTIVITY_NOW);
        }

        expect($recorder->summary(24, ACTIVITY_NOW + 60)->targets[$recorder->userHash('admin@dogearbooks.example')])->toBe(3);
    });

    it('sorts flagged IPs by score', function () {
        $recorder = recorder($cache);

        for ($i = 0; $i < 3; $i++) {
            $recorder->record('103.75.190.11', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + $i);
        }

        for ($i = 0; $i < 10; $i++) {
            $recorder->record('45.148.10.92', Recorder::LOGIN_FAILED, 'POST', '/login', 302, at: ACTIVITY_NOW + $i);
        }

        $flagged = $recorder->summary(24, ACTIVITY_NOW + 60)->flagged;

        expect(array_map(fn ($ip) => [$ip->ip, $ip->score], $flagged))->toBe([['45.148.10.92', 30], ['103.75.190.11', 15]]);
    });

    it('skips protected addresses and counts proxies separately', function () {
        $recorder = recorder($cache);

        for ($i = 0; $i < 25; $i++) {
            $recorder->record('104.16.1.1', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW);
        }

        $recorder->record('159.203.150.232', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW);

        $summary = $recorder->summary(24, ACTIVITY_NOW + 60);

        expect($summary->flagged)->toBe([])
            ->and($summary->totals[Recorder::PROBE])->toBe(0)
            ->and($summary->proxied)->toBe(25)
            ->and($summary->cantSeeVisitors())->toBeTrue()
            ->and(array_map(fn (Issue $i) => $i->kind, $summary->issues()))->toBe(['client_ip_unknown']);
    });

    it('counts safelisted IPs but never flags them', function () {
        $recorder = recorder($cache, fn (string $ip) => $ip === '81.2.69.142');

        for ($i = 0; $i < 5; $i++) {
            $recorder->record('81.2.69.142', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + $i);
        }

        $summary = $recorder->summary(24, ACTIVITY_NOW + 60);

        expect($summary->flagged)->toBe([])
            ->and($summary->totals[Recorder::PROBE])->toBe(5);
    });

    it('caps the hourly index but keeps counting', function () {
        $recorder = recorder($cache);

        for ($i = 1; $i <= Recorder::INDEX_CAP + 5; $i++) {
            $recorder->record('45.'.intdiv($i, 250).'.'.($i % 250).'.9', Recorder::NOT_FOUND, 'GET', '/x', 404, at: ACTIVITY_NOW);
        }

        expect($cache['porro:activity:'.gmdate('YmdH', ACTIVITY_NOW).':i'])->toHaveCount(Recorder::INDEX_CAP)
            ->and($recorder->summary(24, ACTIVITY_NOW + 60)->totals[Recorder::NOT_FOUND])->toBe(Recorder::INDEX_CAP + 5);
    });

    it('only looks back over the window', function () {
        $recorder = recorder($cache);

        for ($i = 0; $i < 3; $i++) {
            $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + $i);
        }

        expect($recorder->summary(24, ACTIVITY_NOW + 25 * 3600)->flagged)->toBe([])
            ->and($recorder->summary(48, ACTIVITY_NOW + 25 * 3600)->flagged)->toHaveCount(1);
    });

    it('raises an exposed file as critical, once per path', function () {
        $recorder = recorder($cache);
        $recorder->exposed('185.220.101.4', '/.env', 200, ACTIVITY_NOW);
        $recorder->exposed('45.148.10.92', '/%2eENV', 200, ACTIVITY_NOW + 5);

        $issues = $recorder->summary(24, ACTIVITY_NOW + 60)->issues();

        expect($issues)->toHaveCount(1)
            ->and($issues[0]->kind)->toBe('exposed_file')
            ->and($issues[0]->severity)->toBe(Issue::CRITICAL)
            ->and($issues[0]->title)->toBe('/.env is publicly readable')
            ->and($issues[0]->detail)->toContain('45.148.10.92')
            ->and($issues[0]->fix)->toBe('location ~ /\.(?!well-known) { deny all; }');
    });

    it('titles the activity issue by the most worrying signal', function () {
        $recorder = recorder($cache);

        foreach (['185.220.101.4', '103.75.190.11'] as $ip) {
            for ($i = 0; $i < 3; $i++) {
                $recorder->record($ip, Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + $i);
            }
        }

        for ($i = 0; $i < 10; $i++) {
            $recorder->record('45.148.10.92', Recorder::LOGIN_FAILED, 'POST', '/login', 302, at: ACTIVITY_NOW + $i);
        }

        $issue = $recorder->summary(24, ACTIVITY_NOW + 60)->issues()[0];

        expect($issue->kind)->toBe('suspicious_activity')
            ->and($issue->severity)->toBe(Issue::WARNING)
            ->and($issue->title)->toBe('3 IPs probing for secrets and admin tools')
            ->and($issue->detail)->toBe('2 IPs probing for secrets and admin tools · 1 IP trying passwords · in the last 24 hours');
    });

    it('fails open when the cache breaks', function () {
        $broken = fn () => throw new RuntimeException('down');
        $recorder = new Recorder($broken, $broken, $broken, new ProtectedRanges, 'key');

        $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404);
        $recorder->exposed('185.220.101.4', '/.env', 200);

        expect($recorder->summary()->flagged)->toBe([]);
    });

    it('ignores unknown signals and invalid IPs', function () {
        $recorder = recorder($cache);
        $recorder->record('185.220.101.4', 'nonsense', 'GET', '/', 200);
        $recorder->record('not-an-ip', Recorder::PROBE, 'GET', '/.env', 404);

        expect($cache)->toBe([]);
    });
});

describe('blocklist', function () {
    beforeEach(function () {
        $this->blocks = memoryStore();
        $this->safe = memoryStore();
        $this->list = new Blocklist($this->blocks, $this->safe, new ProtectedRanges, ['198.51.100.24', ['cidr' => '81.2.69.0/24', 'note' => 'Office']]);
    });

    it('blocks an address or range, normalised', function () {
        $entry = $this->list->block('103.75.190.7/24', 'Scanner network', Entry::MANUAL, null, 'Daniel', '81.3.3.3', ACTIVITY_NOW);

        expect($entry->cidr)->toBe('103.75.190.0/24')
            ->and($this->list->matcher(ACTIVITY_NOW)->match('103.75.190.200'))->toBe('Scanner network')
            ->and($this->list->blocks(ACTIVITY_NOW))->toHaveCount(1);
    });

    it('refuses what would break the site', function (string $value, string $reason, string $message) {
        try {
            $this->list->block($value, 'test', actorIp: '45.148.10.92', now: ACTIVITY_NOW);
            $this->fail('Expected a refusal');
        } catch (Refused $e) {
            expect($e->reason)->toBe($reason)
                ->and($e->getMessage())->toContain($message);
        }
    })->with([
        'not an IP' => ['example.com', Refused::INVALID, 'isn’t an IP address'],
        'too wide v4' => ['103.0.0.0/15', Refused::TOO_WIDE, 'widest allowed is /16'],
        'too wide v6' => ['2a03:b0c0::/32', Refused::TOO_WIDE, 'widest allowed is /48'],
        'Cloudflare' => ['104.16.1.1', Refused::PROTECTED, 'is a Cloudflare address'],
        'Forge' => ['159.203.150.232', Refused::PROTECTED, 'is a Laravel Forge address'],
        'Forge health check' => ['139.59.222.70', Refused::PROTECTED, 'Forge health checks'],
        'range covering Forge' => ['159.203.150.0/24', Refused::PROTECTED, 'covers Laravel Forge addresses'],
        'private' => ['192.168.1.10', Refused::PROTECTED, 'private or reserved'],
        'own IP' => ['45.148.10.92', Refused::OWN_IP, 'your own IP'],
        'range with own IP' => ['45.148.10.0/24', Refused::OWN_IP, 'covers your own IP'],
        'safelisted by config' => ['81.2.69.142', Refused::SAFELISTED, 'Office'],
    ]);

    it('refuses anything overlapping a safelist entry', function () {
        $this->list->safelist('5.6.7.8', 'CI runner', now: ACTIVITY_NOW);

        expect(fn () => $this->list->block('5.6.7.0/24', 'x', now: ACTIVITY_NOW))->toThrow(Refused::class, 'CI runner');
    });

    it('stops at the cap but lets an existing entry be replaced', function () {
        $this->blocks->entries = array_map(fn ($i) => new Entry('45.'.intdiv($i, 250).'.'.($i % 250).'.1', 'x'), range(0, Blocklist::CAP - 1));

        expect(fn () => $this->list->block('46.1.1.1', 'x', now: ACTIVITY_NOW))->toThrow(Refused::class, 'full')
            ->and($this->list->block('45.0.0.1', 'updated', now: ACTIVITY_NOW)->note)->toBe('updated');
    });

    it('needs a label and a confirmation for wide safelist entries', function () {
        expect(fn () => $this->list->safelist('5.6.7.8', ' ', now: ACTIVITY_NOW))->toThrow(Refused::class, 'label')
            ->and(fn () => $this->list->safelist('5.0.0.0/8', 'ISP', now: ACTIVITY_NOW))->toThrow(Refused::class, '16,777,216')
            ->and($this->list->safelist('5.0.0.0/8', 'ISP', confirmWide: true, now: ACTIVITY_NOW)->cidr)->toBe('5.0.0.0/8');
    });

    it('lists config safelist entries first, and won’t remove them', function () {
        $this->list->safelist('5.6.7.8', 'CI runner', now: ACTIVITY_NOW);

        expect(array_map(fn (Entry $e) => [$e->cidr, $e->source], $this->list->safe(ACTIVITY_NOW)))->toBe([
            ['198.51.100.24', Entry::CONFIG], ['81.2.69.0/24', Entry::CONFIG], ['5.6.7.8', Entry::MANUAL],
        ])
            ->and(fn () => $this->list->unsafelist('81.2.69.0/24'))->toThrow(Refused::class, 'config');

        $this->list->unsafelist('5.6.7.8');

        expect($this->list->isSafelisted('5.6.7.8', ACTIVITY_NOW))->toBeFalse()
            ->and($this->list->isSafelisted('81.2.69.142', ACTIVITY_NOW))->toBeTrue();
    });

    it('prunes expired entries and blocks that became protected or safelisted', function () {
        $this->blocks->entries = [
            new Entry('185.220.101.4', 'old', Entry::SUGGESTED, ACTIVITY_NOW - 8 * 86400, ACTIVITY_NOW - 86400),
            new Entry('103.75.190.0/24', 'scanner'),
            new Entry('5.6.7.8', 'mistake'),
            new Entry('159.203.150.232', 'was a scanner, now Forge'),
        ];
        $this->safe->entries = [
            new Entry('5.6.7.8', 'CI runner', Entry::MANUAL, ACTIVITY_NOW),
            new Entry('9.9.9.9', 'load test', Entry::MANUAL, ACTIVITY_NOW, ACTIVITY_NOW - 1),
        ];

        $removed = $this->list->prune(ACTIVITY_NOW);

        expect($removed)->toBe([
            ['list' => 'safelist', 'cidr' => '9.9.9.9', 'why' => 'expired'],
            ['list' => 'blocklist', 'cidr' => '185.220.101.4', 'why' => 'expired'],
            ['list' => 'blocklist', 'cidr' => '5.6.7.8', 'why' => 'now safelisted (CI runner)'],
            ['list' => 'blocklist', 'cidr' => '159.203.150.232', 'why' => 'now a Laravel Forge address'],
        ])
            ->and(array_map(fn (Entry $e) => $e->cidr, $this->list->blocks(ACTIVITY_NOW)))->toBe(['103.75.190.0/24']);
    });

    it('leaves expired entries out of the matcher before they’re pruned', function () {
        $this->blocks->entries = [new Entry('185.220.101.4', 'old', Entry::SUGGESTED, ACTIVITY_NOW - 86400, ACTIVITY_NOW - 1)];

        expect($this->list->matcher(ACTIVITY_NOW)->has('185.220.101.4'))->toBeFalse();
    });

    it('round-trips entries', function () {
        $entry = new Entry('185.220.101.4', 'Probing', Entry::SUGGESTED, ACTIVITY_NOW, ACTIVITY_NOW + 604800, 'Daniel');

        expect(Entry::fromArray($entry->toArray()))->toEqual($entry);
    });
});

describe('nginx', function () {
    it('renders a deny file with the canary, skipping expired entries', function () {
        $file = NginxBlocklist::render([
            new Entry('185.220.101.4', 'x'),
            new Entry('103.75.190.0/24', 'x'),
            new Entry('2a03:b0c0:3:d0::/64', 'x'),
            new Entry('45.148.10.92', 'x', Entry::SUGGESTED, 0, ACTIVITY_NOW - 1),
        ], ACTIVITY_NOW);

        expect($file)->toContain("deny 192.0.2.1;\ndeny 185.220.101.4;\ndeny 103.75.190.0/24;\ndeny 2a03:b0c0:3:d0::/64;\n")
            ->and($file)->not->toContain('45.148.10.92')
            ->and($file)->toStartWith('# Written by Porro');
    });

    it('generates real IP lines from Cloudflare’s ranges', function () {
        $lines = NginxBlocklist::realIp(new ProtectedRanges);

        expect($lines)->toContain("set_real_ip_from 173.245.48.0/20;\n")
            ->and($lines)->toContain("set_real_ip_from 2606:4700::/32;\n")
            ->and($lines)->toEndWith("real_ip_header CF-Connecting-IP;\n");
    });

    it('writes atomically and only when the list changed', function () {
        $path = sys_get_temp_dir().'/porro-nginx-'.bin2hex(random_bytes(4)).'/storage/porro/nginx-blocklist.conf';
        $entries = [new Entry('185.220.101.4', 'x')];

        expect(NginxBlocklist::write($path, NginxBlocklist::render($entries, ACTIVITY_NOW)))->toBeTrue()
            ->and(NginxBlocklist::write($path, NginxBlocklist::render($entries, ACTIVITY_NOW + 60)))->toBeFalse()
            ->and(NginxBlocklist::write($path, NginxBlocklist::render([...$entries, new Entry('103.75.190.11', 'x')], ACTIVITY_NOW + 120)))->toBeTrue()
            ->and(file_get_contents($path))->toContain('deny 103.75.190.11;')
            ->and(glob(dirname($path).'/.*.conf.*'))->toBe([]);
    });
});

describe('sources', function () {
    it('returns plain text bodies', function () {
        $sources = new Sources(fn () => null, fn () => null, fn () => [200, "1.2.3.4\n"]);

        expect($sources->text('GET', 'https://example.test/list'))->toBe("1.2.3.4\n");
    });
});

/**
 * Sources answering canned responses keyed by "METHOD url".
 *
 * @param  array<string, array{0: int, 1: string}>  $responses
 */
function activitySources(array $responses): Sources
{
    $cache = [];

    return new Sources(
        function (string $key) use (&$cache) {
            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value) use (&$cache) {
            $cache[$key] = $value;
        },
        fn (string $method, string $url) => $responses["{$method} {$url}"] ?? [0, ''],
    );
}

describe('countries', function () {
    it('keeps the country Cloudflare sent with each request', function () {
        $recorder = recorder($cache);

        for ($i = 0; $i < 3; $i++) {
            $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, at: ACTIVITY_NOW + $i, country: $i === 2 ? 't1' : 'DE');
        }

        expect($recorder->summary(24, ACTIVITY_NOW + 60)->flagged[0]->country)->toBe('T1');
    });

    it('normalises country codes, dropping unknowns', function (?string $in, ?string $out) {
        expect(Recorder::country($in))->toBe($out);
    })->with([['de', 'DE'], [' GB ', 'GB'], ['T1', 'T1'], ['XX', null], ['', null], [null, null], ['Germany', null]]);

    it('reads CF-IPCountry only from Cloudflare', function () {
        $ranges = new ProtectedRanges;

        expect(ClientIp::country('104.16.1.1', ['CF-IPCountry' => 'nl'], $ranges))->toBe('NL')
            ->and(ClientIp::country('45.148.10.92', ['CF-IPCountry' => 'NL'], $ranges))->toBeNull()
            ->and(ClientIp::country('104.16.1.1', [], $ranges))->toBeNull();
    });

    it('looks nothing up without a country file', function () {
        $countries = new Countries(sys_get_temp_dir().'/porro-countries-'.bin2hex(random_bytes(4)));
        $flagged = [new FlaggedIp('185.220.101.4', [], 0, 'GET', '/', 404, 0, [], [], 5, 'DE'), new FlaggedIp('45.148.10.92', [], 0, 'GET', '/', 404, 0, [], [], 5)];

        expect($countries->available())->toBeFalse()
            ->and($countries->lookup('185.220.101.4'))->toBeNull()
            ->and(array_map(fn ($ip) => $ip->country, $countries->fill($flagged)))->toBe(['DE', null]);
    });

    it('keeps no file when the download isn’t a country database', function () {
        $dir = sys_get_temp_dir().'/porro-countries-'.bin2hex(random_bytes(4));
        $countries = new Countries($dir);
        $urls = [];

        $updated = $countries->update(function (string $url, string $to) use (&$urls) {
            $urls[] = $url;

            return (bool) file_put_contents($to, gzencode('<html>not a database</html>'));
        }, ACTIVITY_NOW);

        expect($updated)->toBeFalse()
            ->and($countries->available())->toBeFalse()
            ->and($urls[0])->toBe('https://download.db-ip.com/free/dbip-country-lite-'.gmdate('Y-m', ACTIVITY_NOW).'.mmdb.gz')
            ->and(glob($dir.'/*'))->toBe([]);
    });

    it('tries last month’s file when this month’s isn’t up yet', function () {
        $urls = [];
        (new Countries(sys_get_temp_dir().'/porro-countries-'.bin2hex(random_bytes(4))))->update(function (string $url) use (&$urls) {
            $urls[] = $url;

            return false;
        }, gmmktime(0, 30, 0, 11, 1, 2026));

        expect($urls)->toBe([
            'https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz',
            'https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz',
        ]);
    });
});

describe('nginx status', function () {
    beforeEach(function () {
        $this->dir = sys_get_temp_dir().'/porro-nginx-'.bin2hex(random_bytes(4));
        mkdir($this->dir.'/sites-enabled', 0755, true);
        mkdir($this->dir.'/forge-conf/example.com/server', 0755, true);
        $this->file = $this->dir.'/storage/nginx-blocklist.conf';
        $this->stamp = $this->dir.'/stamp';
        $this->dirs = [$this->dir.'/sites-enabled', $this->dir.'/forge-conf'];
        $this->check = fn () => NginxStatus::check($this->file, $this->stamp, $this->dirs);
    });

    it('walks through setup, step by step', function () {
        file_put_contents($this->dir.'/sites-enabled/example.com', "server {\n    listen 443;\n}\n");
        expect(($this->check)()['state'])->toBe(NginxStatus::NOT_WRITTEN);

        NginxBlocklist::write($this->file, NginxBlocklist::render([new Entry('185.220.101.4', 'x')]));
        expect(($this->check)()['state'])->toBe(NginxStatus::NOT_INCLUDED);

        file_put_contents($this->dir.'/sites-enabled/example.com', "server {\n    # include {$this->file};\n    real_ip_header CF-Connecting-IP;\n    include {$this->file};\n}\n");
        expect(($this->check)())->toMatchArray(['state' => NginxStatus::WAITING, 'included' => true, 'real_ip' => true, 'config' => $this->dir.'/sites-enabled/example.com']);

        touch($this->stamp, time() + 5);
        expect(($this->check)()['state'])->toBe(NginxStatus::LOADED);

        // A new block: waiting for the next reload again.
        touch($this->file, time() + 10);
        expect(($this->check)()['state'])->toBe(NginxStatus::WAITING);
    });

    it('finds the include in Forge’s per-site config, and ignores commented lines', function () {
        NginxBlocklist::write($this->file, NginxBlocklist::render([]));
        file_put_contents($this->dir.'/forge-conf/example.com/server/porro.conf', "#include {$this->file};\n");
        expect(($this->check)()['included'])->toBeFalse();

        file_put_contents($this->dir.'/forge-conf/example.com/server/porro.conf', "include \"{$this->file}\";\n");
        expect(($this->check)())->toMatchArray(['included' => true, 'real_ip' => false]);
    });

    it('says when it can’t read the config', function () {
        NginxBlocklist::write($this->file, NginxBlocklist::render([]));
        touch($this->stamp, time() + 5);

        expect(NginxStatus::check($this->file, $this->stamp, ['/nonexistent/nginx']))->toMatchArray(['state' => NginxStatus::UNCONFIRMED, 'included' => null]);
    });

    it('gives the reload job for root’s scheduler', function () {
        expect(NginxStatus::reloadJob('/home/forge/example.com/storage/porro/nginx-blocklist.conf'))
            ->toBe('f=/home/forge/example.com/storage/porro/nginx-blocklist.conf; s=/var/tmp/porro-nginx.stamp; [ "$f" -nt "$s" ] && nginx -t -q && systemctl reload nginx && touch "$s"');
    });
});
