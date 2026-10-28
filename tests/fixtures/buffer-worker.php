<?php

/*
 * One "process" in the concurrent flush test: appends lines, flushes, or
 * both, into a store kept in a JSON file that the lock guards.
 *
 * php buffer-worker.php <buffer> <store> <append count> <flushes> <ip>
 */

use Porro\Core\Activity\Buffer;
use Porro\Core\Activity\ProtectedRanges;
use Porro\Core\Activity\Recorder;

require __DIR__.'/../../vendor/autoload.php';

[, $path, $storePath, $appends, $flushes, $ip] = $argv;

$load = fn () => json_decode((string) @file_get_contents($storePath), true) ?: [];
$save = fn (array $data) => file_put_contents($storePath, json_encode($data));

$recorder = new Recorder(
    fn (string $key) => $load()[$key] ?? null,
    function (string $key, mixed $value) use ($load, $save) {
        $data = $load();
        $data[$key] = $value;
        $save($data);
    },
    function (string $key, int $ttl, int $by = 1) use ($load, $save) {
        $data = $load();
        $data[$key] = ($data[$key] ?? 0) + $by;
        $save($data);
    },
    new ProtectedRanges,
    'app-key',
    buffer: new Buffer($path),
    lock: function (Closure $work) use ($storePath) {
        $handle = fopen($storePath.'.lock', 'c');
        flock($handle, LOCK_EX);

        try {
            $work();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    },
);

$now = (int) getenv('PORRO_NOW');

for ($i = 0, $f = 0; $i < (int) $appends || $f < (int) $flushes; $i++) {
    if ($i < (int) $appends) {
        $recorder->record($ip, Recorder::NOT_FOUND, 'GET', "/x{$i}", 404, at: $now);
    }

    if ($f < (int) $flushes && $i % 25 === 0) {
        $recorder->flush($now);
        $f++;
        usleep(3000);
    }
}
