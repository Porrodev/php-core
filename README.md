# porro/php-core

Shared core for the [Porro](https://porro.dev) connectors: parsing site keys, signing reports, reading `composer.lock` and sending reports to Porro.

You don't install this directly. It comes with a connector:

| Connector | For |
|---|---|
| [`porro/laravel-connector`](https://github.com/Porrodev/laravel-connector) | Laravel 11–13 |
| [`porro/filament-connector`](https://github.com/Porrodev/filament-connector) | Filament 3–5 |
| [`porro/statamic-connector`](https://github.com/Porrodev/statamic-connector) | Statamic 5–6 |

## How reports are signed

A site key looks like `porro_{site id}_{seed}`. The seed is the private half of an Ed25519 key pair; Porro stores only the public half. Each report is signed over:

```
{timestamp}\n{nonce}\n{sha256 of body}
```

and sent with `X-Porro-Site`, `X-Porro-Timestamp`, `X-Porro-Nonce` and `X-Porro-Signature` headers. Porro rejects a report outside a 5-minute window or if it has seen the nonce before. If `ext-sodium` isn't available, `paragonie/sodium_compat` provides it in pure PHP.

## What a report says about the server

Each report includes a `system` block, so Porro can flag an end-of-life OS and match Ubuntu and Debian security notices against the server's installed packages:

- `os`: `ID`, `VERSION_ID`, `VERSION_CODENAME` and `PRETTY_NAME` from `/etc/os-release`
- `kernel`: the running kernel (`php_uname('r')`)
- `reboot_required`: whether `/var/run/reboot-required` exists (Debian and Ubuntu)
- `fingerprint`: an HMAC-SHA256 of `/etc/machine-id` under a Porro-specific key, so sites on one server share one record. The machine id itself is never sent.
- `packages`: the installed packages from `/var/lib/dpkg/status` (status `install ok installed` or `hold ok installed`), each with `name`, `version`, `source` (the source package Ubuntu and Debian notices name; the package's own name when it has no `Source:` field) and `arch`, plus `source_version` when the source's version differs from the package's, and `origin` when the package declares one
- `packages_hash`: a SHA-256 of that list. The list itself is only sent when Porro asks for it, because the hash is new to it (the same idea as the `composer.lock` hash): `Client::send()` sees `need_system_packages` in Porro's reply and sends the report once more with the list, so connectors don't need to do anything
- `unattended_upgrades.enabled`: whether `APT::Periodic::Unattended-Upgrade` is set to anything but `"0"` in `/etc/apt/apt.conf.d` (`20auto-upgrades` on a stock server) and the `unattended-upgrades` package is installed
- `unattended_upgrades.last_run_at`: when it last started, from the end of `/var/log/unattended-upgrades/unattended-upgrades.log`, in ISO 8601 with the server's offset. That log is often readable by root only, in which case this is `null`

These are plain file reads, with no `exec`. Anything the PHP process can't read, such as files outside `open_basedir` on shared hosting, is left out: `null`, or `false` for `reboot_required`.

## What a report says about the database

Connectors describe the site's default database connection with `Database::describe($driver, $serverVersion, $host)` and pass it to `Report::database()`, so Porro can flag an end-of-life MySQL, MariaDB or PostgreSQL:

- `engine`: `mysql`, `mariadb`, `pgsql`, `sqlite` or `sqlsrv`. PDO calls MariaDB `mysql`; it's told apart by its version string
- `version`: just the number, e.g. `10.11.6` from `5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1` or `16.4` from `PostgreSQL 16.4 (Ubuntu…) on x86_64…`
- `local`: whether the database is on the same machine (the default host, `localhost`, a loopback address or a unix socket). `null` for SQLite
- `managed`: the service's name when the host is a known managed database (Amazon RDS, DigitalOcean, Laravel Cloud, Azure, PlanetScale, Neon, Supabase, Google Cloud SQL)

The host, database name, user and credentials are never sent. If the connection can't be read, `database` is `null`.

## Developing

```bash
composer install
composer test
```

## Security

Please email security@porro.dev rather than opening an issue. We reply within one working day.

## License

MIT
