<?php

namespace Porro\Core\Activity;

use Closure;
use Throwable;

/**
 * Suspicious requests waiting to be recorded: one short line each,
 * appended to a file on this server, so a request never touches the
 * database. Recorder::flush() turns them into activity in batches.
 *
 * Each server keeps its own file. A flush renames it before reading, so
 * two flushes never read the same lines, and a request that opened the
 * file just before the rename finishes its line first (it holds the lock).
 *
 * Past the cap only a byte per signal is kept, so a flood can't fill the
 * disk and its totals still add up.
 */
final class Buffer
{
    /** Bytes of lines kept before only counting: a few thousand requests, flushed in well under 64 MB. */
    public const CAP = 2 * 1024 * 1024;

    /** One byte per request past the cap, a file per hour; past this, nothing more is kept. */
    public const OVER_CAP = 1024 * 1024;

    /** A taken file this old was left by a flush that died: picked up again. */
    public const ORPHAN_AFTER = 600;

    /** The byte a signal is counted as past the cap. */
    public const OVER = [Recorder::PROBE => 'p', Recorder::LOGIN_FAILED => 'l', Recorder::NOT_FOUND => 'n', Recorder::POST_FLOOD => 'f'];

    private ?bool $usable = null;

    public function __construct(public readonly string $path, private readonly int $cap = self::CAP) {}

    /**
     * Whether lines can be kept here: false on a read-only filesystem
     * (Vapor, say), and the Recorder writes straight to its store instead.
     */
    public function usable(): bool
    {
        if ($this->usable !== null) {
            return $this->usable;
        }

        try {
            $dir = dirname($this->path);

            if (! is_dir($dir)) {
                self::quietly(fn () => mkdir($dir, 0775, true));
            }

            return $this->usable = is_dir($dir) && is_writable($dir) && (! file_exists($this->path) || is_writable($this->path));
        } catch (Throwable) {
            return $this->usable = false;
        }
    }

    /**
     * Adds one line. False when it couldn't, so the caller records it
     * directly. Past the cap a signal is only counted, and anything else
     * dropped, unless $keep: then false, so it's recorded directly.
     *
     * @param  list<mixed>  $line
     * @param  int|null  $at  when the request came, for the hour it's counted in past the cap
     */
    public function append(array $line, ?string $signal = null, bool $keep = false, ?int $at = null): bool
    {
        if (! $this->usable()) {
            return false;
        }

        $data = json_encode($line, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

        if ($data === false) {
            return false;
        }

        $written = $this->write($this->path, $data."\n", $this->cap);

        if ($written === null) {
            return $keep ? false : $this->over($signal, $at ?? time());
        }

        return $written;
    }

    /**
     * Past the cap: one byte for a signal in this hour's file, so totals
     * still add up, and up to OVER_CAP of those. False when the byte
     * couldn't be written, so the request is recorded directly.
     */
    private function over(?string $signal, int $at): bool
    {
        $byte = $signal === null ? null : (self::OVER[$signal] ?? null);

        return $byte === null || $this->write($this->path.'.over-'.gmdate('YmdH', $at), $byte, self::OVER_CAP) !== false;
    }

    /**
     * Appends $data to $file under an exclusive lock: true when written,
     * false when it couldn't be, null when the file is at $cap.
     */
    private function write(string $file, string $data, int $cap): ?bool
    {
        // Twice at most: once more if a flush renamed the file meanwhile.
        for ($try = 0; $try < 2; $try++) {
            $handle = self::quietly(fn () => fopen($file, 'a'));

            if ($handle === false) {
                return false;
            }

            try {
                if (! self::quietly(fn () => flock($handle, LOCK_EX))) {
                    return false;
                }

                $opened = self::quietly(fn () => fstat($handle));
                clearstatcache(true, $file);
                $current = self::quietly(fn () => stat($file));

                if ($opened === false || $current === false || $opened['ino'] !== $current['ino'] || $opened['dev'] !== $current['dev']) {
                    continue;
                }

                if ($opened['size'] >= $cap) {
                    return null;
                }

                return self::quietly(fn () => fwrite($handle, $data)) === strlen($data);
            } finally {
                self::release($handle);
            }
        }

        return false;
    }

    /**
     * Runs $work unless another flush on this server is running. Never
     * waits. The .flushed file's time is when this server last flushed:
     * set only when $work didn't return false (another server held its
     * lock), so a skipped flush stays due.
     */
    public function exclusive(Closure $work): bool
    {
        if (! $this->usable()) {
            return false;
        }

        $handle = self::quietly(fn () => fopen($this->path.'.lock', 'c'));

        if ($handle === false) {
            return false;
        }

        try {
            if (! flock($handle, LOCK_EX | LOCK_NB)) {
                return false;
            }

            if ($work() === false) {
                return false;
            }

            self::quietly(fn () => touch($this->path.'.flushed'));

            return true;
        } finally {
            self::release($handle);
        }
    }

    /**
     * True when there's something to flush and this server hasn't flushed
     * for $seconds. Two stats: cheap enough for a suspicious request.
     */
    public function due(int $seconds = 60, ?int $now = null): bool
    {
        try {
            clearstatcache();

            // Past the cap the file stays full, so this covers the over counts too.
            if (! file_exists($this->path) || filesize($this->path) < 1) {
                return false;
            }

            $last = file_exists($this->path.'.flushed') ? filemtime($this->path.'.flushed') : false;

            return $last === false || $last <= ($now ?? time()) - $seconds;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Deletes everything waiting, unread: for when recording or batching
     * is switched off, so no raw IP stays on disk past 48 hours.
     */
    public function clear(): void
    {
        foreach ([$this->path, ...(glob($this->path.'.over-*') ?: []), ...(glob($this->path.'.*.taking') ?: [])] as $file) {
            if (file_exists($file)) {
                self::quietly(fn () => unlink($file));
            }
        }
    }

    /**
     * @param  resource  $handle
     */
    private static function release($handle): void
    {
        self::quietly(function () use ($handle) {
            flock($handle, LOCK_UN);
            fclose($handle);
        });
    }

    /**
     * Runs a filesystem call without its warning: a failure is handled by
     * what the caller checks next, and a host's error handler mustn't turn
     * it into an exception on a visitor's request.
     */
    private static function quietly(Closure $call): mixed
    {
        set_error_handler(fn () => true);

        try {
            return $call();
        } finally {
            restore_error_handler();
        }
    }

    /**
     * Everything waiting, now removed from disk: the lines, and per hour
     * and signal how many requests past the cap were only counted.
     *
     * @return array{0: list<mixed>, 1: array<string, array<string, int>>}
     */
    public function take(?int $now = null): array
    {
        $lines = [];
        $over = [];

        foreach ($this->claim($now ?? time()) as $file => $hour) {
            $data = $this->drain($file, $hour !== null ? self::OVER_CAP : $this->cap);

            if ($hour !== null) {
                foreach (self::OVER as $signal => $byte) {
                    $over[$hour][$signal] = ($over[$hour][$signal] ?? 0) + substr_count($data, $byte);
                }

                $over[$hour] = array_filter($over[$hour]);

                continue;
            }

            foreach (explode("\n", $data) as $row) {
                $line = $row === '' ? null : json_decode($row, true);

                if (is_array($line)) {
                    $lines[] = $line;
                }
            }
        }

        return [$lines, array_filter($over)];
    }

    /**
     * Renames the live files aside, so new lines start a fresh file and no
     * other flush can read these, plus any a dead flush left behind.
     *
     * @return array<string, string|null> file => the hour of an over count, null for lines
     */
    private function claim(int $now): array
    {
        $id = bin2hex(random_bytes(6));
        $files = [];
        $hour = fn (string $file) => preg_match('/\.over-(\d{10})(\.|$)/', basename($file), $m) ? $m[1] : null;

        // Older lines first: those a dead flush left behind.
        foreach (glob($this->path.'.*.taking') ?: [] as $orphan) {
            if ((int) self::quietly(fn () => filemtime($orphan)) <= $now - self::ORPHAN_AFTER) {
                $files[$orphan] = $hour($orphan);
            }
        }

        foreach ([$this->path, ...(glob($this->path.'.over-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]') ?: [])] as $live) {
            $taken = "{$live}.{$id}.taking";

            if (file_exists($live) && self::quietly(fn () => rename($live, $taken))) {
                $files[$taken] = $hour($live);
            }
        }

        return $files;
    }

    /**
     * Reads a taken file once any request mid-write has finished, then
     * deletes it: a flush that dies after this loses lines rather than
     * counting them twice.
     */
    private function drain(string $file, int $max): string
    {
        $handle = self::quietly(fn () => fopen($file, 'r'));

        if ($handle === false) {
            return '';
        }

        try {
            // No lock, no read: a request could be mid-write. Left for later.
            if (! self::quietly(fn () => flock($handle, LOCK_EX))) {
                return '';
            }

            // A little over the cap: the line that crossed it.
            $data = (string) stream_get_contents($handle, $max + 65536);
            self::quietly(fn () => unlink($file));

            return $data;
        } finally {
            self::release($handle);
        }
    }
}
