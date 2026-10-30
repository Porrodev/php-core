<?php

namespace Porro\Core;

/**
 * Builds the cron line a connector needs and, when the server allows it,
 * adds it to the current user's crontab. Lines Porro adds end with a
 * marker comment so running connect again never adds a second copy.
 */
final class Cron
{
    public const MARKER = '# porro';

    /**
     * The line runs from the project folder through the stable `current`
     * symlink on zero-downtime sites (see stableDirectory()), with plain
     * `php` from cron's PATH: a versioned binary like /usr/bin/php8.3
     * stops working once the server moves to a newer PHP.
     *
     * @param  string  $schedule  e.g. "* * * * *" or "*\/15 * * * *"
     * @param  string  $command  the command to run from the project folder, e.g. "artisan schedule:run"
     */
    public static function line(string $schedule, string $directory, string $command, string $php = 'php'): string
    {
        return sprintf('%s cd %s && %s %s > /dev/null 2>&1 %s', $schedule, escapeshellarg(self::stableDirectory($directory)), escapeshellarg($php), $command, self::MARKER);
    }

    /**
     * The folder cron should cd into. Zero-downtime deploys (Forge,
     * Envoyer, Deployer) run each release from releases/<id>, and the
     * project root resolves to that folder; a line pointing there runs old
     * code after the next deploy and fails silently once the release is
     * pruned. When a sibling `current` symlink points at this release,
     * use that instead.
     */
    public static function stableDirectory(string $directory): string
    {
        $real = realpath($directory);

        if ($real === false) {
            return $directory;
        }

        foreach (array_unique([rtrim($directory, '/'), $real]) as $candidate) {
            if (basename(dirname($candidate)) !== 'releases') {
                continue;
            }

            $current = dirname($candidate, 2).'/current';

            if (realpath($current) === $real) {
                return $current;
            }
        }

        return $directory;
    }

    /**
     * The PHP binary running now, e.g. /usr/bin/php8.3. Under a web server
     * PHP_BINARY can point at php-fpm, which cron can't use. Cron lines
     * use plain `php` instead; see line().
     */
    public static function phpBinary(): string
    {
        $binary = PHP_BINARY;

        if ($binary === '' || str_contains(basename($binary), 'fpm')) {
            return 'php';
        }

        return $binary;
    }

    /**
     * Whether this server lets us read and write the crontab.
     */
    public static function canInstall(?CrontabIo $io = null): bool
    {
        return ($io ?? new CrontabIo)->available();
    }

    /**
     * The current crontab, or null when it can't be read.
     */
    public static function current(?CrontabIo $io = null): ?string
    {
        $io ??= new CrontabIo;

        return $io->available() ? $io->read() : null;
    }

    /**
     * Whether a crontab already runs this command for this project. Paths
     * are compared after resolving symlinks, so a line pointing at
     * /home/forge/site/current matches a site running from a release
     * folder behind it, as zero-downtime deploys on Forge and Envoyer do.
     * A line for an older or pruned release of the same site doesn't
     * match: it runs old code, or nothing at all.
     *
     * @param  string  $command  e.g. "artisan schedule:run" or "craft porro/report"
     */
    public static function hasEntry(string $crontab, string $directory, string $command): bool
    {
        $keyword = trim((string) strrchr(' '.$command, ' '));
        $target = realpath($directory) ?: $directory;

        foreach (preg_split('/\R/', $crontab) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#') || ! str_contains($line, $keyword)) {
                continue;
            }

            preg_match_all('#/[^\s\'";&|]+#', $line, $paths);

            foreach ($paths[0] as $path) {
                // A folder (cd /path) or a script inside one (/path/artisan).
                foreach ([rtrim($path, '/'), dirname($path)] as $folder) {
                    if ($folder === rtrim($directory, '/') || realpath($folder) === $target) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Whether cron already runs this command for this project, looking in
     * the user's crontab and the system ones (/etc/crontab, /etc/cron.d).
     * Null when none of them can be read.
     */
    public static function isScheduled(string $directory, string $command, ?CrontabIo $io = null, string $etc = '/etc'): ?bool
    {
        $io ??= new CrontabIo;
        $sources = [];

        if ($io->available()) {
            $sources[] = $io->read();
        }

        foreach ([$etc.'/crontab', ...(glob($etc.'/cron.d/*') ?: [])] as $file) {
            if (is_file($file) && is_readable($file)) {
                $sources[] = (string) file_get_contents($file);
            }
        }

        if ($sources === []) {
            return null;
        }

        return self::hasEntry(implode("\n", $sources), $directory, $command);
    }

    /**
     * Adds the line unless an equivalent entry is already there. Lines
     * Porro added earlier for this site and command (marked "# porro")
     * that differ from this one, e.g. pointing at a pruned release folder
     * or an old PHP binary, are replaced rather than left beside it.
     * Lines Porro didn't add are never changed.
     */
    public static function install(string $line, string $directory, string $command, ?CrontabIo $io = null): CronResult
    {
        $io ??= new CrontabIo;

        if (! $io->available()) {
            return CronResult::Unavailable;
        }

        $kept = [];
        $current = false;
        $stale = false;

        foreach (preg_split('/\R/', rtrim($io->read())) ?: [] as $existing) {
            if (! self::isOurs($existing, $directory, $command)) {
                $kept[] = $existing;
            } elseif (trim($existing) === trim($line)) {
                $current = true;
                $kept[] = $existing;
            } else {
                $stale = true;
            }
        }

        $crontab = rtrim(implode("\n", $kept));

        if ($current || self::hasEntry($crontab, $directory, $command)) {
            if ($stale && ! $io->write($crontab === '' ? '' : $crontab."\n")) {
                return CronResult::Failed;
            }

            return CronResult::AlreadyInstalled;
        }

        $updated = ($crontab === '' ? '' : $crontab."\n").$line."\n";

        return $io->write($updated) ? CronResult::Installed : CronResult::Failed;
    }

    /**
     * Whether Porro added this line for this command and this site: it
     * carries the marker and points at the project folder (or its
     * current symlink), or at any release folder beside it.
     */
    private static function isOurs(string $line, string $directory, string $command): bool
    {
        $line = trim($line);
        $keyword = trim((string) strrchr(' '.$command, ' '));

        if ($line === '' || str_starts_with($line, '#') || ! str_ends_with($line, self::MARKER) || ! str_contains($line, $keyword)) {
            return false;
        }

        $real = realpath($directory) ?: null;
        $folders = array_unique(array_filter([rtrim($directory, '/'), rtrim(self::stableDirectory($directory), '/'), $real]));
        $releases = [];

        foreach ($folders as $folder) {
            if (basename(dirname($folder)) === 'releases') {
                $releases[] = dirname($folder).'/';
            }
        }

        preg_match_all('#/[^\s\'";&|]+#', $line, $paths);

        foreach ($paths[0] as $path) {
            foreach ([rtrim($path, '/'), dirname($path)] as $folder) {
                if (in_array($folder, $folders, true) || ($real !== null && realpath($folder) === $real)) {
                    return true;
                }

                foreach ($releases as $prefix) {
                    if (str_starts_with($folder.'/', $prefix) && $folder.'/' !== $prefix) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
