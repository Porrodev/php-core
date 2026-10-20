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
     * @param  string  $schedule  e.g. "* * * * *" or "*\/15 * * * *"
     * @param  string  $command  the command to run from the project folder, e.g. "artisan schedule:run"
     */
    public static function line(string $schedule, string $directory, string $command, ?string $php = null): string
    {
        $php ??= self::phpBinary();

        return sprintf('%s cd %s && %s %s > /dev/null 2>&1 %s', $schedule, escapeshellarg($directory), escapeshellarg($php), $command, self::MARKER);
    }

    /**
     * The PHP binary running now, e.g. /usr/bin/php8.3. Under a web server
     * PHP_BINARY can point at php-fpm, which cron can't use.
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
     * Whether a crontab already runs this command from this directory.
     */
    public static function hasEntry(string $crontab, string $directory, string $command): bool
    {
        foreach (preg_split('/\R/', $crontab) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (str_contains($line, $command) && (str_contains($line, $directory) || str_contains($line, escapeshellarg($directory)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Adds the line unless an equivalent entry is already there.
     */
    public static function install(string $line, string $directory, string $command, ?CrontabIo $io = null): CronResult
    {
        $io ??= new CrontabIo;

        if (! $io->available()) {
            return CronResult::Unavailable;
        }

        $crontab = $io->read();

        if (self::hasEntry($crontab, $directory, $command)) {
            return CronResult::AlreadyInstalled;
        }

        $crontab = rtrim($crontab);
        $updated = ($crontab === '' ? '' : $crontab."\n").$line."\n";

        return $io->write($updated) ? CronResult::Installed : CronResult::Failed;
    }
}
