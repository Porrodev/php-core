<?php

namespace Porro\Core\Health;

use DateTimeImmutable;
use Throwable;

/**
 * Issues in what a connector already collects for its report: debug
 * mode, failed jobs, migrations, the queue, backups and health checks.
 * The same rules Porro runs on each report, worded for the site's own
 * control panel. Nothing here touches the network.
 */
final class ReportChecks
{
    private const BACKUP_STALE_HOURS = 48;

    private const QUEUE_STUCK_MINUTES = 30;

    public function __construct(private readonly ?DateTimeImmutable $now = null) {}

    /**
     * @param  array<string, mixed>  $report  Report::toArray()
     * @return list<Issue>
     */
    public function check(array $report): array
    {
        $health = (array) ($report['health'] ?? []);
        $craft = ($report['platform']['name'] ?? null) === 'craft';
        $environment = $report['platform']['environment'] ?? null;

        return array_values(array_filter([
            $this->debug($health, $craft, $environment),
            $this->failedJobs($health, $craft),
            $this->migrations($health, $craft),
            $this->queue($health),
            $this->backup($health),
            ...$this->healthChecks($health),
        ]));
    }

    /**
     * Whether cron runs: the connector records each run, so a missing or
     * old timestamp means it doesn't.
     *
     * @param  string|null  $lastRun  ISO 8601, when cron last ran the connector
     * @param  bool|null  $inCrontab  whether a crontab has the line; null when it can't be read
     * @param  string  $name  "Scheduler" or "Cron"
     * @param  string  $fix  the command that adds the cron line
     */
    public function scheduler(?string $lastRun, ?bool $inCrontab, string $name, string $fix, int $staleMinutes = 60): ?Issue
    {
        $last = self::date($lastRun);

        if ($last && $last > $this->now()->modify("-{$staleMinutes} minutes")) {
            return null;
        }

        if ($last) {
            return new Issue('scheduler_stale', Issue::WARNING, "{$name} hasn’t run since ".$last->format('j M H:i'), 'Scheduled tasks have stopped running', $fix);
        }

        // Just added: give it its first turn.
        if ($inCrontab === true) {
            return new Issue('scheduler_stale', Issue::NOTICE, 'Waiting for the first '.strtolower($name).' run', 'The cron line is there; this clears within a few minutes of it running', null);
        }

        return new Issue('scheduler_stale', Issue::WARNING, "{$name} isn’t running", 'No cron line runs it on this server, so scheduled tasks never happen', $fix);
    }

    /**
     * @param  array<string, mixed>  $health
     */
    private function debug(array $health, bool $craft, mixed $environment): ?Issue
    {
        // Only a problem in production.
        if (($health['debug'] ?? false) !== true || ! in_array($environment, ['production', 'prod', 'live'], true)) {
            return null;
        }

        return new Issue(
            'debug_mode',
            Issue::CRITICAL,
            'Debug mode is on in production',
            $craft
                ? 'Dev mode shows errors, stack traces and template paths to anyone who visits'
                : 'APP_DEBUG shows errors, stack traces and environment values to anyone who visits',
            $craft ? 'Set CRAFT_DEV_MODE=false in .env' : 'Set APP_DEBUG=false in .env',
        );
    }

    /**
     * @param  array<string, mixed>  $health
     */
    private function failedJobs(array $health, bool $craft): ?Issue
    {
        $failed = $health['failed_jobs_24h'] ?? null;

        if (! is_int($failed) || $failed < 1) {
            return null;
        }

        return new Issue(
            'failed_jobs',
            Issue::NOTICE,
            "{$failed} failed ".($failed === 1 ? 'job' : 'jobs').' in the last 24 hours',
            $craft ? 'From Craft’s queue' : 'From the failed_jobs table',
            $craft ? 'Retry or release them in Utilities → Queue Manager once fixed' : 'php artisan queue:retry all, once fixed',
        );
    }

    /**
     * @param  array<string, mixed>  $health
     */
    private function migrations(array $health, bool $craft): ?Issue
    {
        $pending = $health['pending_migrations'] ?? null;

        if (! is_int($pending) || $pending < 1) {
            return null;
        }

        return new Issue(
            'pending_migrations',
            Issue::WARNING,
            "{$pending} ".($pending === 1 ? 'migration' : 'migrations').' not run',
            'Usually a deploy that skipped this step',
            $craft ? 'php craft up' : 'php artisan migrate --force',
        );
    }

    /**
     * Craft's queue has had jobs waiting too long.
     *
     * @param  array<string, mixed>  $health
     */
    private function queue(array $health): ?Issue
    {
        $waiting = $health['queue_waiting'] ?? null;
        $oldest = self::date($health['queue_oldest_waiting_at'] ?? null);

        if (! is_int($waiting) || $waiting < 1 || ! $oldest || $oldest > $this->now()->modify('-'.self::QUEUE_STUCK_MINUTES.' minutes')) {
            return null;
        }

        return new Issue(
            'queue_stuck',
            Issue::WARNING,
            "Queue stuck · {$waiting} ".($waiting === 1 ? 'job' : 'jobs').' waiting',
            'Oldest waiting since '.$oldest->format('j M H:i').(($health['queue_runs_automatically'] ?? false) === true
                ? ' · Craft only runs the queue while someone has the control panel open'
                : ' · the queue worker isn’t picking jobs up'),
            'Run php craft queue/listen as a daemon, or php craft queue/run from cron',
        );
    }

    /**
     * spatie/laravel-backup, when it's installed.
     *
     * @param  array<string, mixed>  $health
     */
    private function backup(array $health): ?Issue
    {
        if (($health['backup_configured'] ?? false) !== true) {
            return null;
        }

        $last = self::date($health['last_backup_at'] ?? null);

        if (! $last) {
            return new Issue('backup_stale', Issue::WARNING, 'No successful backup found', 'spatie/laravel-backup is installed but has no healthy backup', 'php artisan backup:run');
        }

        $hours = (int) floor(($this->now()->getTimestamp() - $last->getTimestamp()) / 3600);

        return $hours >= self::BACKUP_STALE_HOURS
            ? new Issue('backup_stale', Issue::WARNING, "Last backup {$hours} hours ago", 'spatie/laravel-backup · last successful '.$last->format('j M H:i'), 'Check the scheduler runs backup:run')
            : null;
    }

    /**
     * Failing checks from spatie/laravel-health.
     *
     * @param  array<string, mixed>  $health
     * @return list<Issue>
     */
    private function healthChecks(array $health): array
    {
        $issues = [];

        foreach ((array) ($health['checks'] ?? []) as $check) {
            if (is_array($check) && in_array($check['status'] ?? null, ['failed', 'crashed'], true)) {
                $issues[] = new Issue('health_check', Issue::NOTICE, (string) ($check['name'] ?? 'Health check').' check failing', ($check['summary'] ?? null) ?: null);
            }
        }

        return $issues;
    }

    private function now(): DateTimeImmutable
    {
        return $this->now ?? new DateTimeImmutable;
    }

    private static function date(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (Throwable) {
            return null;
        }
    }
}
