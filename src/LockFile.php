<?php

namespace Porro\Core;

/**
 * Reads composer.lock and composer.json. Only names, versions and whether
 * a package is a direct or dev dependency ever leave the site.
 */
final class LockFile
{
    /**
     * @param  array<int, array{name: string, version: string, dev: bool, direct: bool}>  $packages
     */
    private function __construct(
        public readonly string $hash,
        public readonly array $packages,
    ) {}

    public static function read(string $basePath): ?self
    {
        $lockPath = rtrim($basePath, '/').'/composer.lock';

        if (! is_readable($lockPath)) {
            return null;
        }

        $raw = (string) file_get_contents($lockPath);
        $lock = json_decode($raw, true);

        if (! is_array($lock)) {
            return null;
        }

        $json = json_decode((string) @file_get_contents(rtrim($basePath, '/').'/composer.json'), true);
        $direct = array_merge(
            array_keys((array) ($json['require'] ?? [])),
            array_keys((array) ($json['require-dev'] ?? [])),
        );
        $direct = array_flip(array_map('strtolower', $direct));

        $packages = [];

        foreach (['packages' => false, 'packages-dev' => true] as $key => $dev) {
            foreach ((array) ($lock[$key] ?? []) as $package) {
                if (! isset($package['name'], $package['version'])) {
                    continue;
                }

                $packages[] = [
                    'name' => strtolower((string) $package['name']),
                    'version' => (string) $package['version'],
                    'dev' => $dev,
                    'direct' => isset($direct[strtolower((string) $package['name'])]),
                ];
            }
        }

        return new self(hash('sha256', $raw), $packages);
    }
}
