<?php

namespace Porro\Core;

/**
 * The site's database server: which engine and version, whether it runs
 * on the same machine, and whether it's a known managed service. Only
 * those derived facts leave the site; the host, database name, user and
 * credentials never do.
 */
final class Database
{
    private const ENGINES = ['mysql', 'mariadb', 'pgsql', 'sqlite', 'sqlsrv'];

    private const LOCAL_HOSTS = ['', 'localhost'];

    /**
     * Managed database services, by the end of their host names.
     */
    private const MANAGED = [
        '.rds.amazonaws.com' => 'Amazon RDS',
        '.db.ondigitalocean.com' => 'DigitalOcean',
        '.laravel.cloud' => 'Laravel Cloud',
        '.database.azure.com' => 'Azure',
        '.database.windows.net' => 'Azure',
        '.psdb.cloud' => 'PlanetScale',
        '.neon.tech' => 'Neon',
        '.supabase.co' => 'Supabase',
        '.supabase.com' => 'Supabase',
    ];

    // Porro accepts up to this many characters of version.
    private const MAX_VERSION = 50;

    /**
     * Describe a connection from its driver name (PDO's, or Laravel's and
     * Craft's, which match it), the version the server reports and the
     * host it's reached at: a host name or IP, a unix socket path, '' for
     * the driver's default, or null when it isn't known. Null for a driver
     * Porro doesn't know.
     *
     * @return array{engine: string, version: string|null, local: bool|null, managed: string|null}|null
     */
    public static function describe(string $driver, ?string $serverVersion, ?string $host): ?array
    {
        $engine = strtolower(trim($driver));

        if (! in_array($engine, self::ENGINES, true)) {
            return null;
        }

        // MariaDB speaks MySQL's protocol, so PDO calls it mysql.
        if ($engine === 'mysql' && $serverVersion !== null && stripos($serverVersion, 'mariadb') !== false) {
            $engine = 'mariadb';
        }

        if ($engine === 'sqlite') {
            return ['engine' => $engine, 'version' => self::version($serverVersion), 'local' => null, 'managed' => null];
        }

        $host = $host === null ? null : self::host($host);
        $managed = $host === null ? null : self::managed($host);

        return [
            'engine' => $engine,
            'version' => self::version($serverVersion),
            // A Cloud SQL socket is only a proxy to Google's servers.
            'local' => $host === null ? null : $managed === null && self::local($host),
            'managed' => $managed,
        ];
    }

    /**
     * Just the number: "8.0.36" from "8.0.36-0ubuntu0.22.04.1", "10.11.6"
     * from "5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1" (MariaDB's prefix for
     * old replication clients), "16.4" from "PostgreSQL 16.4 (Ubuntu…) on
     * x86_64…" or PDO's "16.4 (Ubuntu 16.4-1.pgdg24.04+1)".
     */
    private static function version(?string $version): ?string
    {
        $version = trim((string) $version);

        if (preg_match('/^5\.5\.5-(\d+\.\d+\.\d+)/', $version, $m)) {
            return $m[1];
        }

        if (! preg_match('/(\d+(?:\.\d+)*)/', $version, $m)) {
            return null;
        }

        // Cutting it short can leave a trailing dot.
        return rtrim(substr($m[1], 0, self::MAX_VERSION), '.');
    }

    /**
     * Lower case, without IPv6 brackets, a port, or SQL Server's "tcp:"
     * and ",1433".
     */
    private static function host(string $host): string
    {
        $host = strtolower(trim($host));

        if ($host === '' || $host[0] === '/') {
            return $host;
        }

        $host = (string) preg_replace(['/^tcp:/', '/,\d+$/'], '', $host);

        if (preg_match('/^\[([^]]+)\](?::\d+)?$/', $host, $m)) {
            return $m[1];
        }

        // One colon is a port; more is a bare IPv6 address.
        return substr_count($host, ':') === 1 ? (string) preg_replace('/:\d*$/', '', $host) : $host;
    }

    /**
     * The driver's default, localhost, a unix socket, or a loopback
     * address: anything in 127.0.0.0/8, or ::1 however it's written.
     */
    private static function local(string $host): bool
    {
        if (in_array($host, self::LOCAL_HOSTS, true) || $host[0] === '/') {
            return true;
        }

        $ip = @inet_pton($host);

        if ($ip === false) {
            return false;
        }

        // An IPv4-mapped IPv6 address (::ffff:127.0.0.1) is the IPv4 one.
        if (strlen($ip) === 16 && str_starts_with($ip, str_repeat("\0", 10)."\xff\xff")) {
            $ip = substr($ip, 12);
        }

        return strlen($ip) === 4 ? $ip[0] === "\x7f" : $ip === inet_pton('::1');
    }

    private static function managed(string $host): ?string
    {
        if (str_starts_with($host, '/cloudsql/')) {
            return 'Google Cloud SQL';
        }

        foreach (self::MANAGED as $suffix => $provider) {
            if (str_ends_with($host, $suffix)) {
                return $provider;
            }
        }

        return null;
    }
}
