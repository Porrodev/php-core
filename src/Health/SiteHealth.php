<?php

namespace Porro\Core\Health;

use DateTimeImmutable;
use Porro\Core\LockFile;
use Porro\Core\SiteKey;
use Throwable;

/**
 * Everything the control panel's "Site health" panel shows: checks run on
 * the site itself, which need no Porro account, and, once the site is
 * connected, its open findings in Porro.
 *
 * Each connector supplies what only it knows (the platform and its
 * version, whether cron runs, the CMS's own update check) and renders the
 * result in its control panel's own style.
 */
final class SiteHealth
{
    /**
     * Kinds Porro also raises from the connector's reports. When Porro's
     * findings are in, these local ones are left out so nothing shows twice.
     */
    public const PORRO_COVERS = [
        'advisory', 'advisory_low', 'debug_mode', 'unsupported_php', 'unsupported_platform',
        'scheduler_stale', 'failed_jobs', 'pending_migrations', 'backup_stale', 'queue_stuck', 'health_check',
    ];

    /** @var list<Issue> */
    private array $issues = [];

    /** @var list<string> */
    private array $checked = [];

    /** @var list<string> */
    private array $unavailable = [];

    public function __construct(
        private readonly Sources $sources,
        private readonly ?DateTimeImmutable $now = null,
    ) {}

    /**
     * PHP's and the platform's support dates.
     *
     * @param  array<string, string|null>  $versions  EndOfLife::PRODUCTS key => installed version, e.g. ['php' => PHP_VERSION, 'craft' => '5.4.1']
     */
    public function endOfLife(array $versions): self
    {
        $eol = new EndOfLife($this->sources, $this->now);

        foreach ($versions as $product => $version) {
            if ($version === null) {
                continue;
            }

            $this->add($eol->check($product, $version));
            $this->checked[] = (EndOfLife::PRODUCTS[$product][2] ?? $product).' '.EndOfLife::cycle($version, EndOfLife::PRODUCTS[$product][1] ?? 2).' support';
        }

        return $this;
    }

    public function advisories(?LockFile $lock): self
    {
        if (! $lock) {
            $this->unavailable[] = 'No composer.lock, so packages weren’t checked for advisories';

            return $this;
        }

        $found = (new Advisories($this->sources))->check($lock);

        if ($found === null) {
            $this->unavailable[] = 'Couldn’t reach Packagist to check for security advisories';

            return $this;
        }

        array_push($this->issues, ...$found);
        $count = count($lock->packages);
        $this->checked[] = $count.' '.($count === 1 ? 'package' : 'packages').' for security advisories';

        return $this;
    }

    /**
     * @param  array<string, string>  $packages  name => label
     * @param  array<string, string|null>  $installed  name => version
     */
    public function updates(array $packages, array $installed): self
    {
        array_push($this->issues, ...(new Updates($this->sources))->check($packages, $installed));
        $this->checked[] = 'updates to '.implode(', ', array_values($packages));

        return $this;
    }

    /**
     * Debug mode, failed jobs, migrations, the queue, backups and health
     * checks, from the report the connector builds.
     *
     * @param  array<string, mixed>  $report
     */
    public function report(array $report): self
    {
        array_push($this->issues, ...(new ReportChecks($this->now))->check($report));
        $this->checked[] = 'debug mode, migrations and failed jobs';

        return $this;
    }

    /**
     * Something only the connector can check, e.g. the CMS's own updates.
     */
    public function add(?Issue $issue, ?string $checked = null): self
    {
        if ($issue) {
            $this->issues[] = $issue;
        }

        if ($checked !== null) {
            $this->checked[] = $checked;
        }

        return $this;
    }

    public function unavailable(string $note): self
    {
        $this->unavailable[] = $note;

        return $this;
    }

    /**
     * The panel's data, as plain arrays so it caches and renders anywhere.
     *
     * @param  SiteKey|null  $key  null when the site isn't connected to Porro
     * @return array{connected: bool, porro: array{ok: bool, findings: list<array<string, mixed>>, site_url: string|null, error: string|null}|null, issues: list<array<string, mixed>>, checked: list<string>, unavailable: list<string>, counts: array{critical: int, warning: int, notice: int}, checked_at: string}
     */
    public function toArray(?SiteKey $key, string $porroUrl): array
    {
        $porro = null;

        if ($key) {
            try {
                $porro = (new PorroFindings($this->sources, $key, $porroUrl))->fetch();
            } catch (Throwable) {
                $porro = ['ok' => false, 'findings' => [], 'site_url' => null, 'error' => 'Couldn’t reach Porro just now.'];
            }
        }

        $issues = $this->issues;

        if ($porro['ok'] ?? false) {
            $issues = array_values(array_filter($issues, fn (Issue $issue) => ! in_array($issue->kind, self::PORRO_COVERS, true)));
        }

        $issues = Issue::sort($issues);
        $all = [...$issues, ...($porro['findings'] ?? [])];
        $counts = ['critical' => 0, 'warning' => 0, 'notice' => 0];

        foreach ($all as $issue) {
            if (! $issue->acknowledged) {
                $counts[$issue->severity]++;
            }
        }

        return [
            'connected' => $key !== null,
            'porro' => $porro === null ? null : [...$porro, 'findings' => array_map(fn (Issue $i) => $i->toArray(), $porro['findings'])],
            'issues' => array_map(fn (Issue $i) => $i->toArray(), $issues),
            'checked' => array_values(array_unique($this->checked)),
            'unavailable' => $this->unavailable,
            'counts' => $counts,
            'checked_at' => ($this->now ?? new DateTimeImmutable)->format(DATE_ATOM),
        ];
    }
}
