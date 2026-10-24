<?php

use Porro\Core\Database;
use Porro\Core\Report;

it('tells MariaDB from MySQL by its version string', function () {
    // With the "5.5.5-" prefix MariaDB sends old replication clients, and without.
    expect(Database::describe('mysql', '5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1', 'localhost'))
        ->toBe(['engine' => 'mariadb', 'version' => '10.11.6', 'local' => true, 'managed' => null])
        ->and(Database::describe('mysql', '11.4.3-MariaDB-log', 'localhost')['engine'])->toBe('mariadb')
        ->and(Database::describe('mysql', '11.4.3-MariaDB-log', 'localhost')['version'])->toBe('11.4.3')
        // Laravel 11's own mariadb driver.
        ->and(Database::describe('mariadb', '10.6.18-MariaDB', '127.0.0.1')['engine'])->toBe('mariadb');
});

it('drops a distro’s suffix from the MySQL version', function () {
    expect(Database::describe('mysql', '8.0.36-0ubuntu0.22.04.1', '127.0.0.1'))
        ->toBe(['engine' => 'mysql', 'version' => '8.0.36', 'local' => true, 'managed' => null]);
});

it('reads the Postgres version from select version() and from PDO', function () {
    expect(Database::describe('pgsql', 'PostgreSQL 16.4 (Ubuntu 16.4-1.pgdg24.04+1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0, 64-bit', '')['version'])->toBe('16.4')
        ->and(Database::describe('pgsql', '16.4 (Ubuntu 16.4-1.pgdg24.04+1)', '')['version'])->toBe('16.4')
        ->and(Database::describe('pgsql', 'PostgreSQL 9.6.24 on x86_64-pc-linux-gnu', '')['version'])->toBe('9.6.24')
        ->and(Database::describe('pgsql', '9.6.24', '')['version'])->toBe('9.6.24');
});

it('leaves the version null when the server doesn’t give one', function () {
    expect(Database::describe('mysql', null, 'localhost')['version'])->toBeNull()
        ->and(Database::describe('mysql', 'unknown', 'localhost')['version'])->toBeNull();
});

it('says whether the database is on the same machine', function (?string $host, ?bool $local) {
    expect(Database::describe('mysql', '8.0.36', $host)['local'])->toBe($local);
})->with([
    'the default' => ['', true],
    'localhost' => ['localhost', true],
    'localhost in capitals' => ['LOCALHOST', true],
    'IPv4 loopback' => ['127.0.0.1', true],
    'IPv4 loopback with a port' => ['127.0.0.1:3306', true],
    'IPv6 loopback' => ['::1', true],
    'IPv6 loopback in brackets' => ['[::1]:3306', true],
    'another IPv4 loopback address' => ['127.0.1.1', true],
    'the end of 127.0.0.0/8' => ['127.255.255.254', true],
    'IPv6 loopback written out' => ['0:0:0:0:0:0:0:1', true],
    'IPv6 loopback with leading zeros' => ['[0000:0000:0000:0000:0000:0000:0000:0001]:5432', true],
    'IPv4-mapped loopback' => ['::ffff:127.0.0.1', true],
    'not quite loopback' => ['128.0.0.1', false],
    'a host name starting 127' => ['127.example.com', false],
    'IPv6 unspecified' => ['::', false],
    'a unix socket' => ['/var/run/mysqld/mysqld.sock', true],
    'another server' => ['10.0.0.12', false],
    'a host name' => ['db.example.com', false],
    'an IPv6 address' => ['2001:db8::12', false],
    'unknown' => [null, null],
]);

it('names known managed database services', function (string $host, string $managed) {
    expect(Database::describe('pgsql', '16.4', $host))->toMatchArray(['local' => false, 'managed' => $managed]);
})->with([
    ['mydb.c9akciq32.eu-west-2.rds.amazonaws.com', 'Amazon RDS'],
    ['db-postgresql-lon1-12345-do-user-1.b.db.ondigitalocean.com:25060', 'DigitalOcean'],
    ['db-9f2c.eu-west-2.public.db.laravel.cloud', 'Laravel Cloud'],
    ['porro.postgres.database.azure.com', 'Azure'],
    ['aws.connect.psdb.cloud', 'PlanetScale'],
    ['ep-cool-darkness-123456.eu-central-1.aws.neon.tech', 'Neon'],
    ['db.abcdefghijkl.supabase.co', 'Supabase'],
    ['aws-0-eu-west-2.pooler.supabase.com', 'Supabase'],
    // A Cloud SQL proxy socket: a socket, but not this machine's database.
    ['/cloudsql/project:europe-west2:instance', 'Google Cloud SQL'],
]);

it('leaves managed null for other hosts', function () {
    expect(Database::describe('mysql', '8.0.36', 'db.example.com')['managed'])->toBeNull()
        // Only at the end of the name.
        ->and(Database::describe('mysql', '8.0.36', 'rds.amazonaws.com.example.com')['managed'])->toBeNull();
});

it('never says where an SQLite database is', function () {
    expect(Database::describe('sqlite', '3.45.1', '/var/www/database/database.sqlite'))
        ->toBe(['engine' => 'sqlite', 'version' => '3.45.1', 'local' => null, 'managed' => null]);
});

it('reads SQL Server hosts', function () {
    expect(Database::describe('sqlsrv', '16.00.4135', 'tcp:sql.example.com,1433'))
        ->toBe(['engine' => 'sqlsrv', 'version' => '16.00.4135', 'local' => false, 'managed' => null])
        ->and(Database::describe('sqlsrv', '16.00.4135', 'tcp:porro.database.windows.net,1433'))->toMatchArray(['local' => false, 'managed' => 'Azure']);
});

it('gives null for a driver it doesn’t know', function () {
    expect(Database::describe('oci', '19.0.0', 'localhost'))->toBeNull()
        ->and(Database::describe('', null, null))->toBeNull();
});

it('keeps versions to 50 characters', function () {
    expect(Database::describe('mysql', str_repeat('1.', 40).'1', '')['version'])->toHaveLength(49)
        ->not->toEndWith('.')
        ->and(Database::describe('mysql', str_repeat('12.', 30).'1', '')['version'])->toHaveLength(50);
});

it('never sends the host', function () {
    $json = json_encode(Database::describe('pgsql', '16.4', 'secret-db.c9akciq32.eu-west-2.rds.amazonaws.com'));

    expect($json)->not->toContain('secret-db');
});

it('adds the database block to the report', function () {
    $database = Database::describe('mysql', '8.0.36', 'localhost');

    expect((new Report('porro/laravel-connector', 'laravel'))->database($database)->toArray()['database'])->toBe($database)
        ->and((new Report('porro/laravel-connector', 'laravel'))->database(null)->toArray())->toHaveKey('database', null);
});
