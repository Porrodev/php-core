<?php

namespace Porro\Core;

/**
 * Reads the site's npm lock file (package-lock.json, pnpm-lock.yaml or
 * yarn.lock) and package.json, for the JavaScript a PHP site builds with
 * (Vite, Tailwind, Alpine…). Only names, versions and whether a package is
 * a direct or dev dependency ever leave the site; the file itself never does.
 */
final class NpmLockFile
{
    private const FILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

    // More than this and the rest are left out, as Porro accepts 5000.
    private const MAX_PACKAGES = 5000;

    /**
     * @param  array<int, array{name: string, version: string, dev: bool, direct: bool}>  $packages
     */
    private function __construct(
        public readonly string $file,
        public readonly string $hash,
        public readonly array $packages,
    ) {}

    public static function read(string $basePath): ?self
    {
        $base = rtrim($basePath, '/');

        foreach (self::FILES as $file) {
            if (is_readable("{$base}/{$file}")) {
                return self::fromFile($base, $file);
            }
        }

        return null;
    }

    private static function fromFile(string $base, string $file): ?self
    {
        $raw = (string) file_get_contents("{$base}/{$file}");
        $manifest = json_decode((string) @file_get_contents("{$base}/package.json"), true);
        $manifest = is_array($manifest) ? $manifest : [];

        $devDirect = array_flip(array_keys((array) ($manifest['devDependencies'] ?? [])));
        $direct = $devDirect + array_flip(array_keys((array) ($manifest['dependencies'] ?? [])))
            + array_flip(array_keys((array) ($manifest['optionalDependencies'] ?? [])));

        $parsed = match ($file) {
            'pnpm-lock.yaml' => self::parsePnpm($raw),
            'yarn.lock' => self::parseYarn($raw),
            default => self::parseNpm($raw),
        };

        if ($parsed === null) {
            return null;
        }

        $packages = [];

        foreach ($parsed as $package) {
            $key = "{$package['name']}@{$package['version']}";

            // One entry per name and version, preferring the top-level copy.
            if (isset($packages[$key]) && ! ($package['topLevel'] ?? true)) {
                continue;
            }

            $packages[$key] = [
                'name' => $package['name'],
                'version' => $package['version'],
                // Lock files that don't mark dev packages fall back to package.json.
                'dev' => $package['dev'] ?? isset($devDirect[$package['name']]),
                'direct' => isset($direct[$package['name']]) && ($package['topLevel'] ?? true),
            ];
        }

        ksort($packages);

        return new self($file, hash('sha256', $raw), array_slice(array_values($packages), 0, self::MAX_PACKAGES));
    }

    /**
     * package-lock.json v2/v3, and v1's nested tree.
     *
     * @return list<array{name: string, version: string, dev?: bool, topLevel?: bool}>|null
     */
    public static function parseNpm(string $raw): ?array
    {
        $lock = json_decode($raw, true);

        if (! is_array($lock)) {
            return null;
        }

        $out = [];

        if (isset($lock['packages']) && is_array($lock['packages'])) {
            foreach ($lock['packages'] as $path => $entry) {
                // "" is the project itself; links point at workspace folders.
                if ($path === '' || ! is_array($entry) || ! empty($entry['link']) || ! isset($entry['version'])) {
                    continue;
                }

                $name = (string) ($entry['name'] ?? substr((string) $path, (int) strrpos((string) $path, 'node_modules/') + 13));

                $out[] = [
                    'name' => $name,
                    'version' => (string) $entry['version'],
                    'dev' => (bool) ($entry['dev'] ?? false),
                    'topLevel' => $path === "node_modules/{$name}",
                ];
            }

            return $out;
        }

        $walk = function (array $deps, int $depth) use (&$walk, &$out): void {
            foreach ($deps as $name => $entry) {
                if (is_array($entry) && isset($entry['version']) && ! str_starts_with((string) $entry['version'], 'file:')) {
                    $out[] = ['name' => (string) $name, 'version' => (string) $entry['version'], 'dev' => (bool) ($entry['dev'] ?? false), 'topLevel' => $depth === 0];
                }

                $walk((array) ($entry['dependencies'] ?? []), $depth + 1);
            }
        };
        $walk((array) ($lock['dependencies'] ?? []), 0);

        return $out;
    }

    /**
     * pnpm-lock.yaml v6–v9: the "packages:" keys carry name and version.
     *
     * @return list<array{name: string, version: string, dev?: bool}>
     */
    public static function parsePnpm(string $raw): array
    {
        $out = [];
        $inPackages = false;
        $current = null;

        foreach (explode("\n", $raw) as $line) {
            if (preg_match('/^\S/', $line)) {
                $inPackages = str_starts_with($line, 'packages:');
                $current = null;

                continue;
            }

            if (! $inPackages) {
                continue;
            }

            // Two-space keys: "  /name@1.2.3:", "  '@scope/name@1.2.3(peer@1)':"
            if (preg_match('/^ {2}([\'"]?)\/?(.+?)\1:\s*$/', $line, $m)) {
                $spec = (string) preg_replace('/\(.*$/', '', $m[2]);
                $at = strrpos($spec, '@');
                $current = $at > 0 ? count($out) : null;

                if ($at > 0) {
                    $out[] = ['name' => substr($spec, 0, $at), 'version' => substr($spec, $at + 1)];
                }

                continue;
            }

            // v6 marks dev-only packages.
            if ($current !== null && preg_match('/^ {4}dev: (true|false)/', $line, $m)) {
                $out[$current]['dev'] = $m[1] === 'true';
            }
        }

        return array_values(array_filter($out, fn (array $package) => (bool) preg_match('/^\d/', $package['version'])));
    }

    /**
     * yarn.lock, classic (v1) or Berry (v2+).
     *
     * @return list<array{name: string, version: string}>
     */
    public static function parseYarn(string $raw): array
    {
        $out = [];
        $name = null;

        foreach (explode("\n", $raw) as $line) {
            if (preg_match('/^\S/', $line) && ! str_starts_with($line, '#') && str_ends_with(rtrim($line), ':')) {
                // '"@scope/name@npm:^1.0.0", "@scope/name@npm:^1.1.0":' → '@scope/name'
                $first = trim(explode(',', $line)[0], " \t\"':");
                $at = strpos($first, '@', 1);
                $name = $at !== false ? substr($first, 0, $at) : null;

                if ($name === '__metadata') {
                    $name = null;
                }

                continue;
            }

            if ($name !== null && preg_match('/^ {2}version:? "?([^"\s]+)"?/', $line, $m)) {
                // Berry lists the project and workspaces too, as 0.0.0-use.local.
                if (! str_contains($m[1], 'use.local')) {
                    $out[] = ['name' => $name, 'version' => $m[1]];
                }

                $name = null;
            }
        }

        return $out;
    }
}
