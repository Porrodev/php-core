<?php

use Porro\Core\Activity\Buffer;
use Porro\Core\Activity\ProtectedRanges;
use Porro\Core\Activity\Recorder;

// 2026-10-27 09:00:00 UTC
const BUFFER_NOW = 1793091600;

function bufferPath(): string
{
    $dir = sys_get_temp_dir().'/porro-buffer-'.bin2hex(random_bytes(4));
    mkdir($dir);

    return "{$dir}/activity.buf";
}

/**
 * A Recorder over an array cache, counting the store's reads and writes.
 *
 * @param  array<string, mixed>  $cache
 * @param  array{get: int, put: int, increment: int, many: int}  $calls
 */
function bufferedRecorder(?Buffer $buffer, ?array &$cache = null, ?array &$calls = null, ?Closure $safelisted = null): Recorder
{
    $cache ??= [];
    $calls = ['get' => 0, 'put' => 0, 'increment' => 0, 'many' => 0];

    return new Recorder(
        function (string $key) use (&$cache, &$calls) {
            $calls['get']++;

            return $cache[$key] ?? null;
        },
        function (string $key, mixed $value) use (&$cache, &$calls) {
            $calls['put']++;
            $cache[$key] = $value;
        },
        function (string $key, int $ttl, int $by = 1) use (&$cache, &$calls) {
            $calls['increment']++;
            $cache[$key] = ($cache[$key] ?? 0) + $by;
        },
        new ProtectedRanges,
        'app-key',
        $safelisted,
        many: function (array $keys) use (&$cache, &$calls) {
            $calls['many']++;

            return array_intersect_key($cache, array_flip($keys));
        },
        buffer: $buffer,
    );
}

/**
 * The same mix of requests, for comparing buffered and direct recording.
 */
function bufferTraffic(Recorder $recorder): void
{
    foreach (range(0, 39) as $i) {
        $at = BUFFER_NOW - 7200 + $i * 170;
        $recorder->record('185.220.101.4', Recorder::NOT_FOUND, 'GET', '/wp-'.($i % 30), 404, at: $at, country: 'de', userAgent: 'curl/8', host: 'Example.com', proxied: $i % 2 === 0);
        $recorder->record('185.220.101.4', Recorder::PROBE, 'get', '/.env', 404, at: $at + 1, userAgent: 'curl/8', category: 'secrets', host: 'example.com', proxied: false);
        $recorder->record('45.33.32.156', Recorder::LOGIN_FAILED, 'POST', '/login', 401, "user{$i}@example.com", at: $at + 2, userAgent: 'Mozilla/5.0');
        $recorder->record('2a01:4f8::7', Recorder::POST_FLOOD, 'POST', '/contact', 200, at: $at + 3, proxied: true);
    }

    $recorder->seen('185.220.101.4', 'GET', '/', 200, 'example.com', 'curl/8', false, BUFFER_NOW - 30);
    $recorder->turnedAway('185.220.101.4', 'POST', '/login', 'example.com', 'curl/8', true, BUFFER_NOW - 20);
    $recorder->record('10.0.0.8', Recorder::PROBE, 'GET', '/.git/config', 404, at: BUFFER_NOW - 10);
    $recorder->exposed('185.220.101.4', '/.git/config', 200, BUFFER_NOW - 5);
}

describe('buffer', function () {
    it('turns buffered requests into the same history as recording them directly', function () {
        $direct = bufferedRecorder(null, $directCache);
        bufferTraffic($direct);

        $buffer = new Buffer(bufferPath());
        $buffered = bufferedRecorder($buffer, $cache);
        bufferTraffic($buffered);

        expect($cache)->toBe([])
            ->and(filesize($buffer->path))->toBeGreaterThan(0);

        expect($buffered->flush(BUFFER_NOW))->toBe(164);

        foreach (['185.220.101.4', '45.33.32.156', '2a01:4f8::7'] as $ip) {
            expect($buffered->history($ip, 48, BUFFER_NOW))->toEqual($direct->history($ip, 48, BUFFER_NOW));
        }

        expect($buffered->summary(24, BUFFER_NOW))->toEqual($direct->summary(24, BUFFER_NOW))
            ->and($buffered->watched(BUFFER_NOW))->toEqualCanonicalizing($direct->watched(BUFFER_NOW))
            ->and($buffered->watched(BUFFER_NOW))->not->toBe([])
            ->and($cache)->toEqual($directCache)
            ->and(file_exists($buffer->path))->toBeFalse();
    });

    it('keeps raw usernames off the disk', function () {
        $buffer = new Buffer(bufferPath());
        bufferedRecorder($buffer)->record('45.33.32.156', Recorder::LOGIN_FAILED, 'POST', '/login', 401, 'alice@example.com', at: BUFFER_NOW);

        expect(file_get_contents($buffer->path))->not->toContain('alice');
    });

    it('flushes a flood of 2,000 requests in a handful of store writes, every one counted', function () {
        $buffer = new Buffer(bufferPath());
        $recorder = bufferedRecorder($buffer, $cache, $calls);

        foreach (range(1, 2000) as $i) {
            $recorder->record('185.220.101.4', Recorder::NOT_FOUND, 'GET', "/x{$i}", 404, at: BUFFER_NOW - 600 + intdiv($i, 4));
        }

        expect($calls)->toBe(['get' => 0, 'put' => 0, 'increment' => 0, 'many' => 0]);

        $recorder->flush(BUFFER_NOW);

        // A read of the index and the watch list, one batch read, and a
        // write each for the record, the index, the watch list and the total.
        expect($calls['get'] + $calls['many'])->toBeLessThanOrEqual(4)
            ->and($calls['put'] + $calls['increment'])->toBeLessThanOrEqual(4);

        $ip = $recorder->history('185.220.101.4', 48, BUFFER_NOW);

        expect($ip->requests)->toBe(2000)
            ->and($ip->counts[Recorder::NOT_FOUND])->toBe(2000)
            ->and($ip->estimated)->toBeFalse()
            ->and($ip->flagged)->toBeTrue()
            ->and($ip->paths)->toHaveCount(Recorder::PATHS_CAP)
            ->and($ip->otherPaths)->toBe(2000 - Recorder::PATHS_CAP);
    });

    it('keeps the index cap when many IPs are flushed at once', function () {
        $buffer = new Buffer(bufferPath());
        $recorder = bufferedRecorder($buffer, $cache);

        foreach (range(1, Recorder::INDEX_CAP + 20) as $i) {
            $recorder->record('45.'.intdiv($i, 250).'.'.($i % 250).'.9', Recorder::NOT_FOUND, 'GET', '/x', 404, at: BUFFER_NOW);
        }

        $recorder->flush(BUFFER_NOW);

        expect(array_filter(array_keys($cache), fn ($k) => str_contains($k, ':ip:')))->toHaveCount(Recorder::INDEX_CAP)
            ->and($recorder->summary(24, BUFFER_NOW + 60)->totals[Recorder::NOT_FOUND])->toBe(Recorder::INDEX_CAP + 20);
    });

    it('only counts once the file reaches its cap, so a flood can’t fill the disk', function () {
        $buffer = new Buffer(bufferPath(), cap: 2000);
        $recorder = bufferedRecorder($buffer, $cache);

        foreach (range(1, 500) as $i) {
            $recorder->record('185.220.101.4', Recorder::NOT_FOUND, 'GET', '/'.str_repeat('a', 150), 404, at: BUFFER_NOW);
        }

        $recorder->seen('185.220.101.4', 'GET', '/', 200, at: BUFFER_NOW);

        expect(filesize($buffer->path))->toBeLessThan(2000 + 400)
            ->and(filesize($buffer->path.'.over'))->toBeLessThan(500);

        expect($recorder->flush(BUFFER_NOW))->toBe(500);

        $ip = $recorder->history('185.220.101.4', 48, BUFFER_NOW);

        expect($recorder->summary(24, BUFFER_NOW)->totals[Recorder::NOT_FOUND])->toBe(500)
            ->and($ip->requests)->toBeLessThan(20)
            ->and(file_exists($buffer->path.'.over'))->toBeFalse();
    });

    it('stops counting once the over count is full too', function () {
        $buffer = new Buffer(bufferPath(), cap: 1);
        file_put_contents($buffer->path, 'x');
        file_put_contents($buffer->path.'.over', str_repeat('n', Buffer::OVER_CAP));

        bufferedRecorder($buffer)->record('185.220.101.4', Recorder::NOT_FOUND, 'GET', '/x', 404, at: BUFFER_NOW);
        clearstatcache();

        expect(filesize($buffer->path.'.over'))->toBe(Buffer::OVER_CAP);
    });

    it('records an exposed file directly once the buffer is full, rather than lose it', function () {
        $buffer = new Buffer(bufferPath(), cap: 1);
        file_put_contents($buffer->path, 'x');
        $recorder = bufferedRecorder($buffer, $cache);

        $recorder->exposed('185.220.101.4', '/.env', 200, BUFFER_NOW);

        expect($cache['porro:activity:exposed'][0]['path'])->toBe('/.env');
    });

    it('records directly when the folder can’t be written', function () {
        $dir = sys_get_temp_dir().'/porro-readonly-'.bin2hex(random_bytes(4));
        mkdir($dir, 0555);
        $buffer = new Buffer("{$dir}/porro/activity.buf");
        $recorder = bufferedRecorder($buffer, $cache);

        $recorder->record('185.220.101.4', Recorder::PROBE, 'GET', '/.env', 404, at: BUFFER_NOW);

        expect($buffer->usable())->toBeFalse()
            ->and($recorder->history('185.220.101.4', 48, BUFFER_NOW)->counts[Recorder::PROBE])->toBe(1)
            ->and($recorder->flush(BUFFER_NOW))->toBe(0);

        chmod($dir, 0755);
    })->skip(fn () => function_exists('posix_getuid') && posix_getuid() === 0, 'root can write anywhere');

    it('skips lines it can’t trust', function () {
        $buffer = new Buffer(bufferPath());
        $good = ['r', '185.220.101.4', Recorder::NOT_FOUND, 'GET', '/x', 404, null, null, null, null, null, BUFFER_NOW, null];

        file_put_contents($buffer->path, implode("\n", [
            json_encode($good),
            '{not json',
            json_encode(['r', 'not-an-ip'] + $good),
            json_encode([...array_slice($good, 0, 2), 'made_up', ...array_slice($good, 3)]),
            json_encode([...array_slice($good, 0, 11), BUFFER_NOW - Recorder::TTL - 1, null]),
            json_encode(['s', ...array_slice($good, 1)]),
            json_encode(array_slice($good, 0, 12)),
            '',
        ]));

        $recorder = bufferedRecorder($buffer, $cache);

        expect($recorder->flush(BUFFER_NOW))->toBe(1)
            ->and($recorder->summary(24, BUFFER_NOW)->totals[Recorder::NOT_FOUND])->toBe(1);
    });

    it('takes each line once, even when flushes run at the same time as requests', function () {
        $path = bufferPath();
        $store = dirname($path).'/store.json';
        $worker = __DIR__.'/fixtures/buffer-worker.php';
        $procs = [];

        // Two servers' worth of requests into one buffer while a third
        // process keeps flushing, and a fourth flushes alongside it.
        foreach ([[600, 0, '185.220.101.4'], [600, 0, '45.33.32.156'], [0, 40, '198.51.100.1'], [0, 40, '198.51.100.1']] as [$appends, $flushes, $ip]) {
            $command = implode(' ', array_map('escapeshellarg', [PHP_BINARY, $worker, $path, $store, (string) $appends, (string) $flushes, $ip]));
            $procs[] = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, [...getenv(), 'PORRO_NOW' => (string) BUFFER_NOW]);
        }

        foreach ($procs as $proc) {
            proc_close($proc);
        }

        $recorder = new Recorder(
            fn (string $key) => (json_decode((string) file_get_contents($store), true) ?: [])[$key] ?? null,
            fn () => null,
            fn () => null,
            new ProtectedRanges,
            'app-key',
            buffer: new Buffer($path),
        );

        // Whatever the last flush left behind.
        $left = (new Buffer($path))->take(BUFFER_NOW)[0];
        $requests = fn (string $ip) => $recorder->history($ip, 48, BUFFER_NOW)?->requests ?? 0;

        expect($requests('185.220.101.4') + count(array_filter($left, fn ($l) => $l[1] === '185.220.101.4')))->toBe(600)
            ->and($requests('45.33.32.156') + count(array_filter($left, fn ($l) => $l[1] === '45.33.32.156')))->toBe(600);
    });

    it('is due once there are lines and this server hasn’t flushed for a minute', function () {
        $buffer = new Buffer(bufferPath());

        expect($buffer->due(60, BUFFER_NOW))->toBeFalse();

        $buffer->append(['r'], Recorder::NOT_FOUND);
        expect($buffer->due(60, time()))->toBeTrue();

        $buffer->exclusive(fn () => null);
        expect($buffer->due(60, time()))->toBeFalse()
            ->and($buffer->due(60, time() + 61))->toBeTrue();
    });

    it('lets only one flush on a server run at a time', function () {
        $buffer = new Buffer(bufferPath());
        $inner = null;

        $outer = $buffer->exclusive(function () use ($buffer, &$inner) {
            $inner = (new Buffer($buffer->path))->exclusive(fn () => null);
        });

        expect($outer)->toBeTrue()->and($inner)->toBeFalse();
    });

    it('picks up lines a flush that died left behind', function () {
        $buffer = new Buffer(bufferPath());
        $line = json_encode(['r', '185.220.101.4', Recorder::NOT_FOUND, 'GET', '/x', 404, null, null, null, null, null, BUFFER_NOW, null]);
        file_put_contents("{$buffer->path}.dead.taking", $line."\n");
        file_put_contents("{$buffer->path}.over.dead2.taking", 'nn');

        expect($buffer->take(time())[0])->toBe([]);

        touch("{$buffer->path}.dead.taking", time() - Buffer::ORPHAN_AFTER - 1);
        touch("{$buffer->path}.over.dead2.taking", time() - Buffer::ORPHAN_AFTER - 1);

        expect($buffer->take(time()))->toEqual([[json_decode($line, true)], [Recorder::NOT_FOUND => 2]]);
    });
});
