<?php

namespace Porro\Core;

/**
 * The server the site runs on: its OS release, running kernel, whether a
 * reboot is pending, and a fingerprint so sites on one server share one
 * record in Porro. Plain file reads only, so it works where exec is off;
 * anything unreadable (shared hosting, open_basedir) is simply left out.
 */
final class System
{
    /**
     * Porro's own key for the machine id, as systemd recommends: the raw
     * id never leaves the server and can't be matched against other apps.
     */
    private const FINGERPRINT_KEY = 'porro-server-fingerprint';

    /**
     * @return array{fingerprint: string|null, os: array{id: string|null, version_id: string|null, version_codename: string|null, pretty_name: string|null}|null, kernel: string|null, reboot_required: bool}
     */
    public static function read(string $root = '/'): array
    {
        $root = rtrim($root, '/');

        return [
            'fingerprint' => self::fingerprint($root),
            'os' => self::osRelease($root),
            'kernel' => $root === '' ? (php_uname('r') ?: null) : self::file("{$root}/proc/sys/kernel/osrelease"),
            // Debian and Ubuntu: a patched kernel or libc is installed but not running yet.
            'reboot_required' => self::exists("{$root}/var/run/reboot-required"),
        ];
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
