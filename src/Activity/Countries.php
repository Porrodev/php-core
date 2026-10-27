<?php

namespace Porro\Core\Activity;

use Closure;
use MaxMind\Db\Reader;
use Throwable;

/**
 * Rough country for an IP, for sites not behind Cloudflare (which sends
 * CF-IPCountry for free). Read from DB-IP's free country file on the
 * site itself: no API, no account, and the IP never leaves the server.
 * A lookup is a few microseconds and only runs for flagged IPs.
 *
 * Data: IP to Country Lite by DB-IP (https://db-ip.com), CC BY 4.0.
 * The panel has to show that attribution wherever these countries show.
 */
final class Countries
{
    public const ATTRIBUTION = 'IP to country data by DB-IP';

    public const ATTRIBUTION_URL = 'https://db-ip.com';

    public const FILE = 'dbip-country-lite.mmdb';

    /** Published on the 1st of each month. */
    public const URL = 'https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz';

    /** About 4MB compressed, 8MB unpacked. */
    public const MAX_BYTES = 20_000_000;

    private ?Reader $reader = null;

    private bool $opened = false;

    public function __construct(private readonly string $dir) {}

    public function available(): bool
    {
        return is_file($this->path());
    }

    /**
     * Two-letter country code, or null when unknown or there's no file.
     */
    public function lookup(string $ip): ?string
    {
        try {
            $record = $this->reader()?->get($ip);
        } catch (Throwable) {
            return null;
        }

        return Recorder::country(is_array($record) ? ($record['country']['iso_code'] ?? null) : null);
    }

    /**
     * Fills in countries Cloudflare didn't send.
     *
     * @param  list<FlaggedIp>  $flagged
     * @return list<FlaggedIp>
     */
    public function fill(array $flagged): array
    {
        return array_map(fn (FlaggedIp $ip) => $ip->country !== null ? $ip : $ip->withCountry($this->lookup($ip->ip)), $flagged);
    }

    /**
     * Downloads this month's file when the one on disk is older (or
     * missing). Written whole and checked before it replaces the old one.
     *
     * @param  (Closure(string $url, string $to, int $maxBytes): bool)|null  $fetch  saves $url to $to; for tests
     * @return bool whether a new file is in place
     */
    public function update(?Closure $fetch = null, ?int $now = null): bool
    {
        $now ??= time();
        $month = gmdate('Y-m', $now);

        if ($this->available() && gmdate('Y-m', (int) filemtime($this->path())) === $month) {
            return false;
        }

        if (! is_dir($this->dir) && ! @mkdir($this->dir, 0755, true) && ! is_dir($this->dir)) {
            return false;
        }

        $gz = $this->path().'.'.bin2hex(random_bytes(4)).'.gz';
        $tmp = substr($gz, 0, -3);

        try {
            // Early on the 1st the new month may not be up yet.
            $ok = ($fetch ?? self::fetch(...))(sprintf(self::URL, $month), $gz, self::MAX_BYTES)
                || ($fetch ?? self::fetch(...))(sprintf(self::URL, gmdate('Y-m', strtotime('first day of last month', $now))), $gz, self::MAX_BYTES);

            if (! $ok || ! self::gunzip($gz, $tmp, self::MAX_BYTES) || ! self::valid($tmp)) {
                return false;
            }

            $this->reader?->close();
            $this->reader = null;
            $this->opened = false;

            return rename($tmp, $this->path());
        } catch (Throwable) {
            return false;
        } finally {
            foreach ([$gz, $tmp] as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
        }
    }

    public function path(): string
    {
        return rtrim($this->dir, '/').'/'.self::FILE;
    }

    private function reader(): ?Reader
    {
        if (! $this->opened) {
            $this->opened = true;

            try {
                $this->reader = $this->available() ? new Reader($this->path()) : null;
            } catch (Throwable) {
                $this->reader = null;
            }
        }

        return $this->reader;
    }

    private static function valid(string $path): bool
    {
        try {
            $reader = new Reader($path);
            $ok = str_contains(strtolower($reader->metadata()->databaseType), 'country');
            $reader->close();

            return $ok;
        } catch (Throwable) {
            return false;
        }
    }

    private static function gunzip(string $from, string $to, int $maxBytes): bool
    {
        $in = @gzopen($from, 'rb');
        $out = @fopen($to, 'wb');

        if ($in === false || $out === false) {
            return false;
        }

        $written = 0;

        while (! gzeof($in) && $written <= $maxBytes) {
            $written += (int) fwrite($out, (string) gzread($in, 65536));
        }

        gzclose($in);
        fclose($out);

        return $written > 0 && $written <= $maxBytes;
    }

    private static function fetch(string $url, string $to, int $maxBytes): bool
    {
        $context = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => false]]);
        $in = @fopen($url, 'rb', false, $context);
        $out = @fopen($to, 'wb');

        if ($in === false || $out === false) {
            return false;
        }

        $copied = stream_copy_to_stream($in, $out, $maxBytes + 1);
        fclose($in);
        fclose($out);

        return $copied !== false && $copied > 0 && $copied <= $maxBytes;
    }
}
