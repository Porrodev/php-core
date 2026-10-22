<?php

namespace Porro\Core;

/**
 * The server the site runs on: its OS release, running kernel, whether a
 * reboot is pending, a fingerprint so sites on one server share one
 * record in Porro, and on Debian and Ubuntu the installed packages and
 * whether unattended-upgrades applies security updates. Plain file reads
 * only, so it works where exec is off; anything unreadable (shared
 * hosting, open_basedir) is simply left out.
 */
final class System
{
    /**
     * Porro's own key for the machine id, as systemd recommends: the raw
     * id never leaves the server and can't be matched against other apps.
     */
    private const FINGERPRINT_KEY = 'porro-server-fingerprint';

    /**
     * How much of the unattended-upgrades log to look through for its last run.
     */
    private const LOG_TAIL_BYTES = 65536;

    /**
     * @return array{fingerprint: string|null, os: array{id: string|null, version_id: string|null, version_codename: string|null, pretty_name: string|null}|null, kernel: string|null, reboot_required: bool, packages: list<array{name: string, version: string, source: string, arch: string, source_version?: string, origin?: string}>|null, packages_hash: string|null, unattended_upgrades: array{enabled: bool|null, last_run_at: string|null}}
     */
    public static function read(string $root = '/'): array
    {
        $root = rtrim($root, '/');
        $packages = self::packages($root);

        return [
            'fingerprint' => self::fingerprint($root),
            'os' => self::osRelease($root),
            'kernel' => $root === '' ? (php_uname('r') ?: null) : self::file("{$root}/proc/sys/kernel/osrelease"),
            // Debian and Ubuntu: a patched kernel or libc is installed but not running yet.
            'reboot_required' => self::exists("{$root}/var/run/reboot-required"),
            'packages' => $packages,
            // Lets Porro ask for the list only when it has changed.
            'packages_hash' => $packages === null ? null : hash('sha256', (string) json_encode($packages, JSON_UNESCAPED_SLASHES)),
            'unattended_upgrades' => [
                'enabled' => self::unattendedUpgrades($root, $packages),
                'last_run_at' => self::lastUnattendedRun($root),
            ],
        ];
    }

    /**
     * Installed packages from dpkg's database, sorted by name and arch.
     * The source package is what Ubuntu and Debian notices name, so it's
     * sent with each; its version only when it differs from the binary's.
     * Origin is only there when the package declares one.
     *
     * @return list<array{name: string, version: string, source: string, arch: string, source_version?: string, origin?: string}>|null
     */
    private static function packages(string $root): ?array
    {
        $path = "{$root}/var/lib/dpkg/status";

        if (! self::exists($path) || ! @is_readable($path) || ! ($handle = @fopen($path, 'r'))) {
            return null;
        }

        $packages = [];
        $fields = [];

        while (true) {
            $line = fgets($handle);

            if ($line === false || trim($line) === '') {
                if ($package = self::package($fields)) {
                    $packages["{$package['name']}:{$package['arch']}"] = $package;
                }

                $fields = [];

                if ($line === false) {
                    break;
                }

                continue;
            }

            // Continuation lines (descriptions, conffiles) start with a space.
            if ($line[0] !== ' ' && $line[0] !== "\t" && preg_match('/^([A-Za-z0-9-]+):\s*(.*)$/', rtrim($line), $m)) {
                $fields[$m[1]] = $m[2];
            }
        }

        fclose($handle);
        ksort($packages, SORT_STRING);

        return array_values($packages);
    }

    /**
     * @param  array<string, string>  $fields
     * @return array{name: string, version: string, source: string, arch: string, source_version?: string, origin?: string}|null
     */
    private static function package(array $fields): ?array
    {
        // "install ok installed", or "hold ok installed": unpacked, configured and in use.
        if (! isset($fields['Package'], $fields['Version']) || ! preg_match('/^\S+ ok installed$/', $fields['Status'] ?? '')) {
            return null;
        }

        // "Source: openssl" or, when the versions differ, "Source: openssl (3.0.13-0ubuntu3.4)".
        preg_match('/^(\S+)(?:\s+\(([^)]+)\))?/', $fields['Source'] ?? '', $source);

        $package = [
            'name' => $fields['Package'],
            'version' => $fields['Version'],
            'source' => ($source[1] ?? '') !== '' ? $source[1] : $fields['Package'],
            'arch' => $fields['Architecture'] ?? 'all',
        ];

        if (isset($source[2]) && $source[2] !== $fields['Version']) {
            $package['source_version'] = $source[2];
        }

        if (($fields['Origin'] ?? '') !== '') {
            $package['origin'] = $fields['Origin'];
        }

        return $package;
    }

    /**
     * Whether APT runs unattended-upgrades: APT::Periodic::Unattended-Upgrade
     * set to anything but "0" in apt.conf.d (20auto-upgrades on a stock
     * server; later files win), and the package installed. Null when
     * apt.conf.d can't be read.
     *
     * @param  list<array{name: string}>|null  $packages
     */
    private static function unattendedUpgrades(string $root, ?array $packages): ?bool
    {
        $dir = "{$root}/etc/apt/apt.conf.d";
        $files = self::exists($dir) ? @scandir($dir) : false;

        if ($files === false) {
            return null;
        }

        $value = null;

        foreach ($files as $file) {
            $text = $file[0] === '.' ? null : self::file("{$dir}/{$file}");

            // Skip commented-out lines; keep the last value set.
            if ($text !== null && preg_match_all('#^\s*APT::Periodic::Unattended-Upgrade\s+"([^"]*)"\s*;#mi', $text, $m)) {
                $value = end($m[1]);
            }
        }

        if ($value === null || $value === '0' || $value === '') {
            return false;
        }

        return $packages === null || in_array('unattended-upgrades', array_column($packages, 'name'), true);
    }

    /**
     * When unattended-upgrades last started, from the end of its log, in
     * ISO 8601 with the server's offset. Null if the log isn't readable
     * (it's usually root-only) or has no run since it was rotated.
     */
    private static function lastUnattendedRun(string $root): ?string
    {
        $path = "{$root}/var/log/unattended-upgrades/unattended-upgrades.log";

        if (! self::exists($path) || ! @is_readable($path) || ! ($size = @filesize($path))) {
            return null;
        }

        $tail = @file_get_contents($path, false, null, max(0, $size - self::LOG_TAIL_BYTES));

        if ($tail === false || ! preg_match_all('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)? INFO Starting unattended upgrades script/m', $tail, $m)) {
            return null;
        }

        try {
            return (new \DateTimeImmutable(end($m[1]), self::timezone($root)))->format(DATE_ATOM);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * The server's timezone, which the log is written in: /etc/localtime's
     * zoneinfo link, else /etc/timezone, else UTC.
     */
    private static function timezone(string $root): \DateTimeZone
    {
        $link = self::exists("{$root}/etc/localtime") ? @readlink("{$root}/etc/localtime") : false;
        $name = $link !== false && preg_match('#zoneinfo/(.+)$#', $link, $m) ? $m[1] : self::file("{$root}/etc/timezone");

        try {
            return new \DateTimeZone($name ?: 'UTC');
        } catch (\Exception) {
            return new \DateTimeZone('UTC');
        }
    }

    private static function fingerprint(string $root): ?string
    {
        foreach (["{$root}/etc/machine-id", "{$root}/var/lib/dbus/machine-id"] as $path) {
            $id = self::file($path);

            if ($id !== null && preg_match('/^[a-f0-9]{32}$/', $id)) {
                return hash_hmac('sha256', $id, self::FINGERPRINT_KEY);
            }
        }

        return null;
    }

    /**
     * @return array{id: string|null, version_id: string|null, version_codename: string|null, pretty_name: string|null}|null
     */
    private static function osRelease(string $root): ?array
    {
        $text = self::file("{$root}/etc/os-release") ?? self::file("{$root}/usr/lib/os-release");

        if ($text === null) {
            return null;
        }

        $values = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            if (preg_match('/^([A-Z_]+)=(.*)$/', trim($line), $m)) {
                $values[$m[1]] = trim($m[2], "\"'");
            }
        }

        return [
            'id' => $values['ID'] ?? null,
            'version_id' => $values['VERSION_ID'] ?? null,
            'version_codename' => $values['VERSION_CODENAME'] ?? null,
            'pretty_name' => $values['PRETTY_NAME'] ?? null,
        ];
    }

    private static function file(string $path): ?string
    {
        if (! self::exists($path) || ! @is_readable($path)) {
            return null;
        }

        $contents = @file_get_contents($path, length: 8192);

        return $contents === false ? null : trim($contents);
    }

    private static function exists(string $path): bool
    {
        // open_basedir turns file checks outside it into warnings.
        return @file_exists($path);
    }
}
