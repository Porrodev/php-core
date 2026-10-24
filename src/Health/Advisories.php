<?php

namespace Porro\Core\Health;

use Composer\Semver\Semver;
use Porro\Core\LockFile;
use Throwable;

/**
 * Known security advisories for the packages in composer.lock, from
 * Packagist's security advisories API (the one `composer audit` uses).
 * Only package names leave the site; versions are matched here.
 */
final class Advisories
{
    private const TTL = 21600;

    private const URL = 'https://packagist.org/api/security-advisories/';

    public function __construct(private readonly Sources $sources) {}

    /**
     * One issue per affected package: high and critical advisories in the
     * site's own packages are critical; low and medium ones, and anything
     * in a dev dependency, are notices. Null when Packagist can't be reached.
     *
     * @return list<Issue>|null
     */
    public function check(LockFile $lock): ?array
    {
        $installed = [];

        foreach ($lock->packages as $package) {
            if (! str_starts_with($package['version'], 'dev-')) {
                $installed[$package['name']] = $package;
            }
        }

        if ($installed === []) {
            return [];
        }

        // Keyed by the lock file, so an update is checked straight away.
        $advisories = $this->sources->remember('advisories:'.$lock->hash, self::TTL, function () use ($installed) {
            $body = http_build_query(['packages' => array_keys($installed)]);
            $data = $this->sources->json('POST', self::URL, ['Content-Type' => 'application/x-www-form-urlencoded'], $body);

            return is_array($data['advisories'] ?? null) ? $data['advisories'] : null;
        });

        if (! is_array($advisories)) {
            return null;
        }

        $issues = [];

        foreach ($advisories as $name => $list) {
            $package = $installed[strtolower((string) $name)] ?? null;

            if (! $package || ! is_array($list)) {
                continue;
            }

            $matching = array_values(array_filter($list, fn ($advisory) => is_array($advisory)
                && is_string($advisory['affectedVersions'] ?? null)
                && self::affects($package['version'], $advisory['affectedVersions'])));

            if ($matching !== []) {
                $issues[] = $this->issue($package, $matching);
            }
        }

        return Issue::sort($issues);
    }

    public static function affects(string $version, string $constraint): bool
    {
        try {
            return Semver::satisfies($version, $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param  array{name: string, version: string, dev: bool, direct: bool}  $package
     * @param  list<array<string, mixed>>  $advisories
     */
    private function issue(array $package, array $advisories): Issue
    {
        $order = ['critical' => 0, 'high' => 1, 'moderate' => 2, 'medium' => 2, 'low' => 3];
        usort($advisories, fn ($a, $b) => ($order[strtolower((string) ($a['severity'] ?? ''))] ?? 1) <=> ($order[strtolower((string) ($b['severity'] ?? ''))] ?? 1));

        $worst = $advisories[0];
        $severity = strtolower((string) ($worst['severity'] ?? ''));
        $serious = ! in_array($severity, ['low', 'medium', 'moderate'], true) && ! $package['dev'];
        $label = $severity !== '' ? ucfirst($severity) : 'Security';
        $count = count($advisories);
        $cves = array_slice(array_filter(array_map(fn ($a) => $a['cve'] ?? null, $advisories)), 0, 3);

        return new Issue(
            $serious ? 'advisory' : 'advisory_low',
            $serious ? Issue::CRITICAL : Issue::NOTICE,
            ($count === 1 ? "{$label} advisory in {$package['name']}" : "{$count} advisories in {$package['name']}").($package['dev'] ? ' · dev dependency' : ''),
            implode(' · ', array_filter([
                "Installed {$package['version']}",
                self::truncate(($count === 1 ? '' : "worst {$label}: ").(string) ($worst['title'] ?? ''), 140),
                implode(', ', $cves),
            ])),
            "composer update {$package['name']}",
            // Only web links become links in the control panel.
            is_string($worst['link'] ?? null) && preg_match('#^https?://#i', $worst['link']) ? $worst['link'] : null,
        );
    }

    /**
     * The first $length characters, without needing mbstring.
     */
    private static function truncate(string $text, int $length): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, $length);
        }

        return preg_match('/^.{0,'.$length.'}/su', $text, $m) ? $m[0] : substr($text, 0, $length);
    }

    /**
     * Forgets the cached advisories for this lock file, e.g. after a
     * "check again".
     */
    public function forget(LockFile $lock): void
    {
        $this->sources->forget('advisories:'.$lock->hash);
    }
}
