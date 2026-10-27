<?php

namespace Porro\Core\Activity;

/**
 * Whether nginx on this server has the blocklist, found by looking and
 * never by running anything:
 *
 *  - written: the deny file exists (the sync writes it every minute)
 *  - included: a file in nginx's site config includes it (read-only; Forge
 *    leaves these readable, but some hosts don't, so it can be unknown)
 *  - reloaded: the reload job's stamp is newer than the file, so nginx
 *    reloaded (and passed nginx -t) since the last change
 */
final class NginxStatus
{
    public const LOADED = 'loaded';

    public const NOT_WRITTEN = 'not_written';

    public const NOT_INCLUDED = 'not_included';

    public const WAITING = 'waiting_reload';

    /** Reloads happen, but the config can't be read to confirm the include. */
    public const UNCONFIRMED = 'unconfirmed';

    /** Touched by the reload job each time it reloads nginx. */
    public const STAMP = '/var/tmp/porro-nginx.stamp';

    /** Where Forge and most hosts keep site config. */
    public const CONFIG_DIRS = ['/etc/nginx/sites-enabled', '/etc/nginx/conf.d', '/etc/nginx/forge-conf'];

    /** Enough for any real site config; stops a stray huge file being read. */
    private const MAX_FILE = 1_000_000;

    /**
     * @param  list<string>  $configDirs
     * @return array{state: string, written: int|null, reloaded: int|null, included: bool|null, real_ip: bool|null, config: string|null}
     */
    public static function check(string $path, string $stamp = self::STAMP, array $configDirs = self::CONFIG_DIRS): array
    {
        $written = is_file($path) ? (int) filemtime($path) : null;
        $reloaded = @is_file($stamp) ? (int) @filemtime($stamp) : null;
        [$included, $realIp, $config] = self::findInclude($path, $configDirs);

        $state = match (true) {
            $written === null => self::NOT_WRITTEN,
            $included === false => self::NOT_INCLUDED,
            $reloaded === null || $reloaded < $written => self::WAITING,
            $included === null => self::UNCONFIRMED,
            default => self::LOADED,
        };

        return ['state' => $state, 'written' => $written, 'reloaded' => $reloaded, 'included' => $included, 'real_ip' => $realIp, 'config' => $config];
    }

    /**
     * The command for a root scheduled job, every minute: reloads nginx only
     * when the file is newer than the stamp and the config passes nginx -t.
     */
    public static function reloadJob(string $path, string $stamp = self::STAMP): string
    {
        return sprintf('f=%s; s=%s; [ "$f" -nt "$s" ] && nginx -t -q && systemctl reload nginx && touch "$s"', $path, $stamp);
    }

    /**
     * @param  list<string>  $dirs
     * @return array{0: bool|null, 1: bool|null, 2: string|null} included, real IP set up in that file, which file
     */
    private static function findInclude(string $path, array $dirs): array
    {
        $readable = false;

        foreach ($dirs as $dir) {
            foreach (self::files($dir) as $file) {
                $readable = true;
                $contents = @file_get_contents($file, false, null, 0, self::MAX_FILE);

                if (! is_string($contents)) {
                    continue;
                }

                // Any include of the file: commented-out lines don't count.
                $pattern = '/^\s*include\s+["\']?'.preg_quote($path, '/').'["\']?\s*;/m';

                if (preg_match($pattern, $contents)) {
                    // Set up in the site's config, or carried in Porro's own file.
                    $realIp = (bool) preg_match('/^\s*real_ip_header\s+/m', $contents)
                        || (bool) preg_match('/^\s*real_ip_header\s+/m', (string) @file_get_contents($path, false, null, 0, self::MAX_FILE));

                    return [true, $realIp, $file];
                }
            }
        }

        return [$readable ? false : null, null, null];
    }

    /**
     * Files under $dir, two levels deep (forge-conf/{site}/server/*.conf).
     *
     * @return list<string>
     */
    private static function files(string $dir, int $depth = 0): array
    {
        if (! @is_dir($dir) || ! @is_readable($dir)) {
            return [];
        }

        $files = [];

        foreach (@scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $full = $dir.'/'.$name;

            if (@is_file($full) && @is_readable($full)) {
                $files[] = $full;
            } elseif ($depth < 2 && @is_dir($full)) {
                array_push($files, ...self::files($full, $depth + 1));
            }
        }

        return $files;
    }
}
