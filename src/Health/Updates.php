<?php

namespace Porro\Core\Health;

use Composer\Semver\VersionParser;
use Throwable;

/**
 * Newer releases of a few key packages (the framework and its admin
 * panel), from Packagist. Only the release line the site is on is
 * compared: a new major version is an upgrade, not an update, and the
 * end-of-life check covers when that matters.
 */
final class Updates
{
    private const TTL = 43200;

    public function __construct(private readonly Sources $sources) {}

    /**
     * @param  array<string, string>  $packages  name => label, e.g. ['laravel/framework' => 'Laravel']
     * @param  array<string, string|null>  $installed  name => installed version
     * @return list<Issue>
     */
    public function check(array $packages, array $installed): array
    {
        $issues = [];

        foreach ($packages as $name => $label) {
            $version = $installed[$name] ?? null;
            $latest = $version ? $this->latestInLine($name, $version) : null;

            if ($latest !== null) {
                $issues[] = new Issue(
                    'updates_waiting',
                    Issue::NOTICE,
                    "{$label} {$latest} is available",
                    "Installed {$version}",
                    "composer update {$name} -W",
                );
            }
        }

        return $issues;
    }

    /**
     * The newest stable release with the same major version, when it's
     * newer than $version.
     */
    public function latestInLine(string $package, string $version): ?string
    {
        $releases = $this->sources->remember('releases:'.$package, self::TTL, fn () => $this->releases($package));

        if (! is_array($releases) || ! preg_match('/^v?(\d+)\./', $version, $m)) {
            return null;
        }

        try {
            $parser = new VersionParser;
            $current = $parser->normalize($version);
        } catch (Throwable) {
            return null;
        }

        $newest = $releases[$m[1]] ?? null;

        try {
            return is_string($newest) && version_compare($parser->normalize($newest), $current, '>') ? ltrim($newest, 'v') : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The newest stable version of each major, from Packagist's metadata.
     *
     * @return array<string, string>|null major => version
     */
    private function releases(string $package): ?array
    {
        $data = $this->sources->json('GET', "https://repo.packagist.org/p2/{$package}.json");
        $versions = $data['packages'][$package] ?? null;

        if (! is_array($versions)) {
            return null;
        }

        $newest = [];

        foreach ($versions as $entry) {
            $version = is_array($entry) ? (string) ($entry['version'] ?? '') : '';

            if (! preg_match('/^v?(\d+)\./', $version, $m) || VersionParser::parseStability($version) !== 'stable') {
                continue;
            }

            if (! isset($newest[$m[1]]) || version_compare(ltrim($version, 'v'), ltrim($newest[$m[1]], 'v'), '>')) {
                $newest[$m[1]] = $version;
            }
        }

        return $newest;
    }
}
