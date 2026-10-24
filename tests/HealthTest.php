<?php

use Porro\Core\Health\Advisories;
use Porro\Core\Health\EndOfLife;
use Porro\Core\Health\Issue;
use Porro\Core\Health\PorroFindings;
use Porro\Core\Health\ReportChecks;
use Porro\Core\Health\SiteHealth;
use Porro\Core\Health\Sources;
use Porro\Core\Health\Updates;
use Porro\Core\LockFile;
use Porro\Core\SiteKey;

/**
 * Sources backed by an array cache and canned HTTP responses keyed by
 * "METHOD url". Requests it has no response for fail like a network error.
 *
 * @param  array<string, array{0: int, 1: string}>  $responses
 * @param  list<array<string, mixed>>  $calls
 * @param  array<string, mixed>  $cache
 */
function fakeSources(array $responses, array &$calls = [], array &$cache = []): Sources
{
    return new Sources(
        function (string $key) use (&$cache) {
            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value, int $ttl) use (&$cache) {
            $cache[$key] = $value;
        },
        function (string $method, string $url, array $headers, ?string $body) use (&$responses, &$calls) {
            $calls[] = compact('method', 'url', 'headers', 'body');

            return $responses["{$method} {$url}"] ?? [0, ''];
        },
    );
}

/**
 * @param  array<int, array{name: string, version: string}>  $packages
 * @param  array<int, array{name: string, version: string}>  $dev
 */
function lockWith(array $packages, array $dev = []): LockFile
{
    $dir = sys_get_temp_dir().'/porro-health-'.bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents("{$dir}/composer.lock", json_encode(['packages' => $packages, 'packages-dev' => $dev]));
    file_put_contents("{$dir}/composer.json", '{}');

    return LockFile::read($dir);
}

function eolResponse(array $cycles): array
{
    return [200, json_encode($cycles)];
}

describe('end of life', function () {
    it('flags a version past security support with the upgrade path', function () {
        $sources = fakeSources(['GET https://endoflife.date/api/php.json' => eolResponse([
            ['cycle' => '8.4', 'eol' => '2028-12-31'],
            ['cycle' => '8.1', 'eol' => '2025-12-31'],
        ])]);

        $issue = (new EndOfLife($sources, new DateTimeImmutable('2026-10-23')))->check('php', '8.1.29');

        expect($issue->kind)->toBe('unsupported_php')
            ->and($issue->severity)->toBe(Issue::WARNING)
            ->and($issue->title)->toBe('PHP 8.1 is past security support')
            ->and($issue->detail)->toBe('PHP 8.1.29 · security support ended 31 Dec 2025 · it no longer gets security fixes · upgrade to PHP 8.4')
            ->and($issue->fix)->toBeNull();
    });

    it('warns 90 days ahead and says nothing before that', function () {
        $sources = fakeSources(['GET https://endoflife.date/api/craft-cms.json' => eolResponse([
            ['cycle' => '5', 'eol' => false],
            ['cycle' => '4', 'eol' => '2026-12-31'],
        ])]);

        $soon = (new EndOfLife($sources, new DateTimeImmutable('2026-10-23')))->check('craft', '4.12.3');
        $later = (new EndOfLife($sources, new DateTimeImmutable('2026-06-01')))->check('craft', '4.12.3');

        expect($soon->kind)->toBe('platform_ending_soon')
            ->and($soon->severity)->toBe(Issue::NOTICE)
            ->and($soon->title)->toBe('Craft 4 security support ends in 69 days')
            ->and($soon->detail)->toBe('Craft 4.12.3 · ends 31 Dec 2026 · upgrade to Craft 5')
            ->and($later)->toBeNull();
    });

    it('falls back to the bundled dates when endoflife.date is down, and caches the failure', function () {
        $calls = [];
        $cache = [];
        $sources = fakeSources([], $calls, $cache);
        $eol = new EndOfLife($sources, new DateTimeImmutable('2026-10-23'));

        expect($eol->check('php', '7.4.33')?->title)->toBe('PHP 7.4 is past security support')
            ->and($eol->check('php', '8.5.0'))->toBeNull()
            ->and($calls)->toHaveCount(1);
    });

    it('reads versions with a v in front', function () {
        $sources = fakeSources(['GET https://endoflife.date/api/statamic.json' => eolResponse([['cycle' => '6', 'eol' => '2027-12-31'], ['cycle' => '5', 'eol' => '2026-12-31']])]);

        expect((new EndOfLife($sources, new DateTimeImmutable('2026-10-23')))->check('statamic', 'v5.74.7')->detail)->toBe('Statamic 5.74.7 · ends 31 Dec 2026 · upgrade to Statamic 6');
    });

    it('ignores products and versions it doesn’t know', function () {
        $eol = new EndOfLife(fakeSources([]), new DateTimeImmutable('2026-10-23'));

        expect($eol->check('wordpress', '6.0'))->toBeNull()
            ->and($eol->check('php', 'dev-main'))->toBeNull()
            ->and($eol->check('php', null))->toBeNull();
    });
});

describe('advisories', function () {
    $response = [200, json_encode(['advisories' => [
        'guzzlehttp/guzzle' => [
            ['title' => 'Cookie scope', 'link' => 'https://github.com/advisories/GHSA-1', 'cve' => 'CVE-2026-1', 'affectedVersions' => '<7.15.2', 'severity' => 'medium'],
            ['title' => 'Host bypass', 'link' => 'https://github.com/advisories/GHSA-2', 'cve' => 'CVE-2026-2', 'affectedVersions' => '>=8.0.0,<8.0.1|<7.15.2', 'severity' => 'high'],
        ],
        'monolog/monolog' => [
            ['title' => 'Old bug', 'cve' => null, 'affectedVersions' => '<2.0.0', 'severity' => 'critical'],
        ],
        'acme/odd' => [
            ['title' => 'Odd link', 'link' => 'javascript:alert(1)', 'affectedVersions' => '<2.0.0', 'severity' => 'low'],
        ],
        'phpunit/phpunit' => [
            ['title' => 'Dev only', 'cve' => null, 'affectedVersions' => '<99', 'severity' => 'critical'],
        ],
    ]])];

    it('matches advisories against installed versions and ranks them like Porro', function () use ($response) {
        $calls = [];
        $lock = lockWith(
            [['name' => 'guzzlehttp/guzzle', 'version' => '7.9.0'], ['name' => 'monolog/monolog', 'version' => '3.7.0'], ['name' => 'acme/fork', 'version' => 'dev-main'], ['name' => 'acme/odd', 'version' => '1.0.0']],
            [['name' => 'phpunit/phpunit', 'version' => '11.0.0']],
        );

        $issues = (new Advisories(fakeSources(['POST https://packagist.org/api/security-advisories/' => $response], $calls)))->check($lock);

        expect($issues)->toHaveCount(3)
            ->and($issues[0]->kind)->toBe('advisory')
            ->and($issues[0]->severity)->toBe(Issue::CRITICAL)
            ->and($issues[0]->title)->toBe('2 advisories in guzzlehttp/guzzle')
            ->and($issues[0]->detail)->toBe('Installed 7.9.0 · worst High: Host bypass · CVE-2026-2, CVE-2026-1')
            ->and($issues[0]->url)->toBe('https://github.com/advisories/GHSA-2')
            ->and($issues[0]->fix)->toBe('composer update guzzlehttp/guzzle')
            ->and($issues[1]->kind)->toBe('advisory_low')
            ->and($issues[1]->title)->toBe('Low advisory in acme/odd')
            ->and($issues[1]->url)->toBeNull()
            ->and($issues[2]->title)->toBe('Critical advisory in phpunit/phpunit · dev dependency');

        // Names only: no versions, and dev branches aren't asked about.
        parse_str($calls[0]['body'], $sent);
        expect($sent['packages'])->toBe(['guzzlehttp/guzzle', 'monolog/monolog', 'acme/odd', 'phpunit/phpunit']);
    });

    it('asks Packagist once per lock file', function () use ($response) {
        $calls = [];
        $cache = [];
        $sources = fakeSources(['POST https://packagist.org/api/security-advisories/' => $response], $calls, $cache);
        $lock = lockWith([['name' => 'guzzlehttp/guzzle', 'version' => '7.9.0']]);

        (new Advisories($sources))->check($lock);
        (new Advisories($sources))->check($lock);

        expect($calls)->toHaveCount(1);
    });

    it('says so when Packagist can’t be reached', function () {
        expect((new Advisories(fakeSources([])))->check(lockWith([['name' => 'a/b', 'version' => '1.0.0']])))->toBeNull();
    });
});

describe('updates', function () {
    it('offers the newest release on the installed major only', function () {
        $sources = fakeSources(['GET https://repo.packagist.org/p2/laravel/framework.json' => [200, json_encode(['packages' => ['laravel/framework' => [
            ['version' => 'v13.1.0'], ['version' => 'v12.40.2'], ['version' => 'v12.41.0-beta1'], ['version' => 'v12.39.0'], ['version' => 'v11.46.1'],
        ]]])]]);

        $updates = new Updates($sources);

        expect($updates->check(['laravel/framework' => 'Laravel'], ['laravel/framework' => 'v12.31.0']))
            ->sequence(fn ($issue) => $issue->title->toBe('Laravel 12.40.2 is available')->fix->toBe('composer update laravel/framework -W'))
            ->and($updates->check(['laravel/framework' => 'Laravel'], ['laravel/framework' => '12.40.2']))->toBe([])
            ->and($updates->check(['laravel/framework' => 'Laravel'], ['laravel/framework' => null]))->toBe([]);
    });
});

describe('report checks', function () {
    $now = new DateTimeImmutable('2026-10-23T12:00:00+00:00');

    it('raises what Porro raises from a report', function () use ($now) {
        $issues = (new ReportChecks($now))->check([
            'platform' => ['name' => 'laravel', 'environment' => 'production'],
            'health' => [
                'debug' => true,
                'failed_jobs_24h' => 3,
                'pending_migrations' => 1,
                'backup_configured' => true,
                'last_backup_at' => '2026-10-20T12:00:00+00:00',
                'checks' => [['name' => 'Disk space', 'status' => 'failed', 'summary' => '95% used'], ['name' => 'Cache', 'status' => 'ok']],
            ],
        ]);

        expect(array_map(fn ($i) => $i->title, $issues))->toBe([
            'Debug mode is on in production',
            '3 failed jobs in the last 24 hours',
            '1 migration not run',
            'Last backup 72 hours ago',
            'Disk space check failing',
        ]);
    });

    it('leaves debug mode alone outside production and words Craft’s own way', function () use ($now) {
        $local = (new ReportChecks($now))->check(['platform' => ['name' => 'craft', 'environment' => 'dev'], 'health' => ['debug' => true]]);
        $craft = (new ReportChecks($now))->check(['platform' => ['name' => 'craft', 'environment' => 'production'], 'health' => [
            'debug' => true, 'pending_migrations' => 2, 'queue_waiting' => 4, 'queue_oldest_waiting_at' => '2026-10-23T10:00:00+00:00', 'queue_runs_automatically' => true,
        ]]);

        expect($local)->toBe([])
            ->and($craft[0]->detail)->toEndWith('set CRAFT_DEV_MODE=false in .env')
            ->and($craft[0]->fix)->toBeNull()
            ->and($craft[1]->fix)->toBe('php craft up')
            ->and($craft[2]->title)->toBe('Queue stuck · 4 jobs waiting');
    });

    it('checks the scheduler from its last run and the crontab', function () use ($now) {
        $checks = new ReportChecks($now);

        expect($checks->scheduler('2026-10-23T11:45:00+00:00', null, 'Scheduler', 'php artisan porro:cron'))->toBeNull()
            ->and($checks->scheduler('2026-10-23T09:00:00+00:00', true, 'Scheduler', 'php artisan porro:cron')->title)->toBe('Scheduler hasn’t run since 23 Oct 09:00')
            ->and($checks->scheduler(null, true, 'Cron', 'php craft porro/cron')->severity)->toBe(Issue::NOTICE)
            ->and($checks->scheduler(null, false, 'Cron', 'php craft porro/cron'))
            ->title->toBe('Cron isn’t running')
            ->severity->toBe(Issue::WARNING)
            ->fix->toBe('php craft porro/cron');
    });
});

describe('sources', function () {
    it('treats a response over the size limit as a failure', function () {
        $calls = [];
        $cache = [];
        $limits = [];
        $sources = new Sources(
            function (string $key) use (&$cache) {
                return $cache[$key] ?? null;
            },
            function (string $key, mixed $value) use (&$cache) {
                $cache[$key] = $value;
            },
            function (string $method, string $url, array $headers, ?string $body, int $timeout, int $maxBytes) use (&$limits) {
                $limits[] = $maxBytes;

                return [200, json_encode(['data' => str_repeat('a', $url === 'https://big.test' ? 2000 : 10)])];
            },
            maxBytes: 1000,
        );

        expect($sources->json('GET', 'https://big.test'))->toBeNull()
            ->and($sources->json('GET', 'https://small.test'))->toBe(['data' => str_repeat('a', 10)])
            ->and($limits)->toBe([1000, 1000]);
    });
});

describe('porro findings', function () {
    it('reads findings with a signed request and caches them', function () {
        $key = siteKey();
        $calls = [];
        $cache = [];
        $sources = fakeSources(['GET https://porro.test/api/v1/findings' => [200, json_encode([
            'ok' => true,
            'site' => ['url' => 'https://porro.test/acme/sites/example'],
            'findings' => [
                ['kind' => 'ssl_expiring', 'rank' => 3, 'title' => 'SSL expires in 9 days', 'detail' => 'R11', 'url' => 'https://porro.test/acme/sites/example', 'scope' => 'site'],
                ['kind' => 'down', 'rank' => 1, 'title' => 'Down', 'url' => 'javascript:alert(1)', 'scope' => 'site'],
                ['kind' => 'os_unsupported', 'rank' => 2, 'title' => 'Ubuntu 20.04 past security support', 'scope' => 'server', 'acknowledged' => true],
            ],
        ])]], $calls, $cache);

        $findings = new PorroFindings($sources, SiteKey::parse($key['token']), 'https://porro.test/');
        $result = $findings->fetch();
        $findings->fetch();

        expect($calls)->toHaveCount(1)
            ->and(signatureIsValid($calls[0]['headers'], '', $key['public'], 'GET', '/api/v1/findings'))->toBeTrue()
            ->and($result['ok'])->toBeTrue()
            ->and($result['site_url'])->toBe('https://porro.test/acme/sites/example')
            ->and(array_map(fn ($i) => [$i->title, $i->severity, $i->scope, $i->url], $result['findings']))->toBe([
                ['Down', Issue::CRITICAL, 'site', null],
                ['Ubuntu 20.04 past security support', Issue::CRITICAL, 'server', null],
                ['SSL expires in 9 days', Issue::WARNING, 'site', 'https://porro.test/acme/sites/example'],
            ]);
    });

    it('caches per Porro and per key', function () {
        $key = siteKey();
        $calls = [];
        $cache = [];
        $response = [200, json_encode(['ok' => true, 'site' => ['url' => null], 'findings' => []])];
        $sources = fakeSources(['GET https://porro.test/api/v1/findings' => $response, 'GET https://staging.porro.test/api/v1/findings' => $response], $calls, $cache);

        (new PorroFindings($sources, SiteKey::parse($key['token']), 'https://porro.test'))->fetch();
        (new PorroFindings($sources, SiteKey::parse($key['token']), 'https://porro.test/'))->fetch();
        (new PorroFindings($sources, SiteKey::parse($key['token']), 'https://staging.porro.test'))->fetch();
        // A new key for the same site.
        (new PorroFindings($sources, SiteKey::parse(siteKey()['token']), 'https://porro.test'))->fetch();

        expect(array_column($calls, 'url'))->toBe([
            'https://porro.test/api/v1/findings',
            'https://staging.porro.test/api/v1/findings',
            'https://porro.test/api/v1/findings',
        ]);
    });

    it('forgets its own cache entry', function () {
        $calls = [];
        $cache = [];
        $sources = fakeSources(['GET https://porro.test/api/v1/findings' => [200, json_encode(['ok' => true, 'findings' => []])]], $calls, $cache);
        $findings = new PorroFindings($sources, SiteKey::parse(siteKey()['token']), 'https://porro.test');

        $findings->fetch();
        $findings->forget();
        $findings->fetch();

        expect($calls)->toHaveCount(2);
    });

    it('reports when Porro can’t be reached', function () {
        $result = (new PorroFindings(fakeSources([]), SiteKey::parse(siteKey()['token']), 'https://porro.test'))->fetch();

        expect($result['ok'])->toBeFalse()->and($result['error'])->not->toBeNull();
    });
});

describe('site health', function () {
    it('runs the local checks and counts what needs attention', function () {
        $health = (new SiteHealth(fakeSources([
            'GET https://endoflife.date/api/php.json' => eolResponse([['cycle' => '8.1', 'eol' => '2025-12-31'], ['cycle' => '8.4', 'eol' => '2028-12-31']]),
            'POST https://packagist.org/api/security-advisories/' => [200, '{"advisories":[]}'],
        ]), new DateTimeImmutable('2026-10-23')))
            ->endOfLife(['php' => '8.1.2'])
            ->advisories(lockWith([['name' => 'a/b', 'version' => '1.0.0']]))
            ->report(['platform' => ['name' => 'laravel', 'environment' => 'production'], 'health' => ['debug' => true]])
            ->toArray(null, 'https://porro.test');

        expect($health['connected'])->toBeFalse()
            ->and($health['porro'])->toBeNull()
            ->and(array_column($health['issues'], 'title'))->toBe(['Debug mode is on in production', 'PHP 8.1 is past security support'])
            ->and($health['counts'])->toBe(['critical' => 1, 'warning' => 1, 'notice' => 0])
            ->and($health['checked'])->toContain('PHP 8.1 support', '1 package for security advisories');
    });

    it('leaves out local issues Porro already has once connected', function () {
        $key = siteKey();
        $health = (new SiteHealth(fakeSources([
            'GET https://porro.test/api/v1/findings' => [200, json_encode(['ok' => true, 'site' => ['url' => null], 'findings' => [
                ['kind' => 'debug_mode', 'rank' => 2, 'title' => 'Debug mode on in production', 'scope' => 'site'],
            ]])],
        ])))
            ->report(['platform' => ['name' => 'laravel', 'environment' => 'production'], 'health' => ['debug' => true]])
            ->add(new Issue('cms_update', Issue::NOTICE, 'Statamic 6.3 is available'))
            ->toArray(SiteKey::parse($key['token']), 'https://porro.test');

        expect($health['connected'])->toBeTrue()
            ->and(array_column($health['issues'], 'title'))->toBe(['Statamic 6.3 is available'])
            ->and(array_column($health['porro']['findings'], 'title'))->toBe(['Debug mode on in production'])
            ->and($health['counts'])->toBe(['critical' => 1, 'warning' => 0, 'notice' => 1]);
    });

    it('keeps local issues Porro hasn’t raised, even of kinds it covers', function () {
        $health = (new SiteHealth(fakeSources([
            'GET https://porro.test/api/v1/findings' => [200, json_encode(['ok' => true, 'site' => ['url' => null], 'findings' => [
                ['kind' => 'debug_mode', 'rank' => 2, 'title' => 'Debug mode on in production', 'scope' => 'site'],
            ]])],
        ])))
            ->report(['platform' => ['name' => 'laravel', 'environment' => 'production'], 'health' => ['debug' => true, 'pending_migrations' => 1]])
            ->toArray(SiteKey::parse(siteKey()['token']), 'https://porro.test');

        expect(array_column($health['issues'], 'kind'))->toBe(['pending_migrations'])
            ->and(array_column($health['porro']['findings'], 'kind'))->toBe(['debug_mode']);
    });

    it('keeps every local issue when Porro can’t be reached', function () {
        $health = (new SiteHealth(fakeSources([])))
            ->report(['platform' => ['name' => 'laravel', 'environment' => 'production'], 'health' => ['debug' => true]])
            ->toArray(SiteKey::parse(siteKey()['token']), 'https://porro.test');

        expect($health['porro']['ok'])->toBeFalse()
            ->and(array_column($health['issues'], 'kind'))->toBe(['debug_mode']);
    });
});
