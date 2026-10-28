<?php

namespace Porro\Tools\ProbeSources;

/**
 * What changed between two candidates documents, and the pull request
 * body that shows it.
 */
final class Changes
{
    /** Rows in the PR table before it says "and N more". */
    public const MAX_ROWS = 150;

    /** @var list<array<string, mixed>> */
    public readonly array $added;

    /** @var list<array<string, mixed>> */
    public readonly array $removed;

    /**
     * @param  array<string, mixed>|null  $old  the committed document, or null on a first run
     * @param  array<string, mixed>  $new
     */
    public function __construct(private readonly ?array $old, private readonly array $new)
    {
        $before = self::keyed($old ?? []);
        $after = self::keyed($new);

        $this->added = array_values(array_diff_key($after, $before));
        $this->removed = array_values(array_diff_key($before, $after));
    }

    public function any(): bool
    {
        return $this->added !== [] || $this->removed !== [];
    }

    public function markdown(): string
    {
        $crs = $this->new['crs'];
        $kev = $this->new['kev'];

        $lines = [
            'Weekly refresh of `resources/probes/candidates.json`. **Nothing here changes what Probes matches.** '
                .'Each candidate needs a review before it moves into `Probes::PATTERNS`: see "Reviewing probe candidates" in the README.',
            '',
            "- OWASP Core Rule Set `{$crs['tag']}` (Apache-2.0)",
            "- CISA KEV catalog `{$kev['catalog_version']}`: {$kev['cves']} CVEs added in the last {$kev['window_days']} days, "
                .count($kev['no_template']).' without a nuclei template',
            "- ProjectDiscovery nuclei-templates `{$kev['nuclei']['ref']}` (MIT)",
            '',
            '**'.count($this->added).' new, '.count($this->removed).' gone** '
                .'(gone means Probes matches it now, or the CVE left the 90-day window).',
        ];

        if ($this->added !== []) {
            $lines[] = '';
            $lines[] = '| Source | Path | Suggested category | From |';
            $lines[] = '| --- | --- | --- | --- |';

            foreach (array_slice($this->added, 0, self::MAX_ROWS) as $entry) {
                $from = isset($entry['cve'])
                    ? "[{$entry['cve']}]({$entry['source_url']})"
                    : "[{$entry['file']}]({$entry['source_url']})";

                $lines[] = '| '.$entry['source'].' | '.self::code($entry['path']).' | `'.$entry['category'].'` | '.$from.' |';
            }

            if (count($this->added) > self::MAX_ROWS) {
                $lines[] = '';
                $lines[] = '…and '.(count($this->added) - self::MAX_ROWS).' more in the diff.';
            }
        }

        if ($this->removed !== []) {
            $lines[] = '';
            $lines[] = '<details><summary>Gone</summary>';
            $lines[] = '';

            foreach (array_slice($this->removed, 0, self::MAX_ROWS) as $entry) {
                $lines[] = '- '.$entry['source'].' '.self::code($entry['path']);
            }

            $lines[] = '';
            $lines[] = '</details>';
        }

        $lines[] = '';
        $lines[] = 'Opened by `.github/workflows/probe-sources.yml`. Never auto-merged.';

        return implode("\n", $lines)."\n";
    }

    /**
     * @param  array<string, mixed>  $doc
     * @return array<string, array<string, mixed>>
     */
    private static function keyed(array $doc): array
    {
        $keyed = [];

        foreach (['crs', 'kev'] as $source) {
            foreach ($doc[$source]['entries'] ?? [] as $entry) {
                $keyed[$source.' '.$entry['path']] = ['source' => strtoupper($source)] + $entry;
            }
        }

        return $keyed;
    }

    /**
     * A path as inline code that can't break the table.
     */
    private static function code(string $path): string
    {
        if (strlen($path) > 120) {
            $path = substr($path, 0, 117).'...';
        }

        return '`'.str_replace(['`', '|'], ["'", '\\|'], $path).'`';
    }
}
