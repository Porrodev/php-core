<?php

namespace Porro\Core\Activity;

use RuntimeException;

/**
 * The deny file nginx includes, and the real-IP lines that have to come
 * before it when the site is behind Cloudflare (or nginx would deny
 * Cloudflare instead of the visitor).
 */
final class NginxBlocklist
{
    /**
     * Always denied: a documentation address no real visitor has. Its
     * presence shows the file is Porro's and was written in full.
     */
    public const CANARY = '192.0.2.1';

    /**
     * @param  list<Entry>  $entries
     */
    public static function render(array $entries, ?int $now = null, ?string $realIp = null): string
    {
        $now ??= time();
        $lines = [
            '# Written by Porro. Changes here are overwritten: manage the blocklist in the control panel.',
            '# '.gmdate('Y-m-d H:i:s', $now).' UTC · '.count($entries).' '.(count($entries) === 1 ? 'entry' : 'entries'),
        ];

        // Behind Cloudflare, the real IP lines travel in the same file, so
        // the site needs one include and they stay current. nginx resolves
        // the real IP before it checks deny, wherever the lines sit.
        if ($realIp !== null) {
            $lines[] = rtrim($realIp);
        }

        $lines[] = 'deny '.self::CANARY.';';

        foreach ($entries as $entry) {
            if (! $entry->isExpired($now) && Cidr::isValid($entry->cidr)) {
                $lines[] = 'deny '.Cidr::parse($entry->cidr).';';
            }
        }

        return implode("\n", $lines)."\n";
    }

    /**
     * The lines that make nginx see the visitor behind Cloudflare.
     */
    public static function realIp(ProtectedRanges $ranges): string
    {
        $lines = ['# Cloudflare real IP, from Cloudflare’s published ranges'];

        foreach ($ranges->ranges()[ProtectedRanges::CLOUDFLARE] as $range) {
            $lines[] = "set_real_ip_from {$range};";
        }

        $lines[] = 'real_ip_header CF-Connecting-IP;';

        return implode("\n", $lines)."\n";
    }

    /**
     * Writes $contents to $path all at once, so nginx never reads half a
     * file. Skips the write when nothing changed, so the reload job
     * (which watches the file's time) only reloads when it must.
     *
     * @return bool whether the file changed
     */
    public static function write(string $path, string $contents): bool
    {
        if (is_file($path) && self::withoutStamp((string) file_get_contents($path)) === self::withoutStamp($contents)) {
            return false;
        }

        $dir = dirname($path);

        if (! is_dir($dir) && ! @mkdir($dir, 0755, true) && ! is_dir($dir)) {
            throw new RuntimeException("Couldn’t create {$dir}");
        }

        $temp = $dir.'/.'.basename($path).'.'.bin2hex(random_bytes(4));

        if (file_put_contents($temp, $contents) === false || ! rename($temp, $path)) {
            @unlink($temp);

            throw new RuntimeException("Couldn’t write {$path}");
        }

        return true;
    }

    private static function withoutStamp(string $contents): string
    {
        return (string) preg_replace('/^# \d{4}-\d{2}-\d{2} [^\n]*\n/m', '', $contents);
    }
}
