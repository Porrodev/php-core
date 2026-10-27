# porro/php-core

Shared core for the [Porro](https://porro.dev) connectors: parsing site keys, signing reports, reading `composer.lock`, sending reports to Porro and the site health checks the connectors show in the control panel.

You don't install this directly. It comes with a connector:

| Connector | For |
|---|---|
| [`porro/laravel-connector`](https://github.com/Porrodev/laravel-connector) | Laravel 11–13 |
| [`porro/filament-connector`](https://github.com/Porrodev/filament-connector) | Filament 3–5 |
| [`porro/statamic-connector`](https://github.com/Porrodev/statamic-connector) | Statamic 5–6 |
| [`porro/craft-connector`](https://github.com/Porrodev/craft-connector) | Craft 4–5 |

## How requests are signed

A site key looks like `porro_{site id}_{seed}`. The seed is the private half of an Ed25519 key pair; Porro stores only the public half. Each request to Porro (a report, or reading findings) is signed over:

```
connector-v1\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{sha256 of body}
```

for example `connector-v1\nPOST\n/api/v1/reports\n…`, so a signature only works for the endpoint it was made for. It's sent with `X-Porro-Site`, `X-Porro-Timestamp`, `X-Porro-Nonce` and `X-Porro-Signature` headers. Porro rejects a request outside a 5-minute window or if it has seen the nonce before. Before 0.2.1 the signature was over `{timestamp}\n{nonce}\n{sha256 of body}` alone; Porro still accepts that for reports for now, but not for findings. If `ext-sodium` isn't available, `paragonie/sodium_compat` provides it in pure PHP.

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

## Site health checks

`Porro\Core\Health` runs the checks behind each connector's Site health panel, on the site itself and without a Porro account:

- `EndOfLife`: PHP, Laravel, Craft and Statamic versions past, or within 90 days of, the end of security support. Dates come from [endoflife.date](https://endoflife.date), fetched once a day, with a copy in `data/endoflife.json` for when it can't be reached.
- `Advisories`: known security advisories for the packages in `composer.lock`, from [Packagist's security advisories API](https://packagist.org/apidoc#list-security-advisories) (the one `composer audit` uses). Only package names are sent; versions are matched on the site with `composer/semver`. High and critical advisories rank like Porro's "Act now"; low and medium ones, and anything in a dev dependency, as notices.
- `Updates`: the newest release of a few key packages on the major version the site runs, from Packagist.
- `ReportChecks`: debug mode in production, failed jobs, pending migrations, a stuck queue, stale backups, failing health checks and whether cron runs, from what the connector already collects. The same rules Porro runs on each report.
- `PorroFindings`: once connected, the site's open findings in Porro and its server's, read from `GET /api/v1/findings` with a request signed by the site key (over an empty body), cached for five minutes per Porro URL and key. Local issues are only left out when Porro has an open finding of the same kind.
- `SiteHealth` puts them together for the panel, leaving out local issues Porro already raises once its findings are in.

Network results go through the connector's own cache via `Sources` (failures for ten minutes), so a control panel page rarely waits on the network and an unreachable API never slows every page.

## Suspicious activity and blocking

`Porro\Core\Activity` is what each connector's Activity and Blocking panels are built on. It works on the site alone, and IP addresses never leave it.

- `ClientIp`: the visitor's address. Uses the framework's own value, which respects the site's trusted proxies, and believes `CF-Connecting-IP` only when the request came from a Cloudflare range.
- `Probes`: paths scanners ask for that no visitor of a Laravel, Craft or Statamic site does. These are dotfiles and secrets, VCS folders, WordPress, database admin tools and known exploits. Paths the app really serves can be excluded.
- `Recorder`: counts probes, failed logins, 404 bursts and form floods in the connector's cache.
  - Counts go into hourly buckets kept for 48 hours.
  - Only those events are recorded, so ordinary page views cost nothing, and every write fails open.
  - Usernames are kept only as keyed hashes.
  - `summary()` returns the flagged IPs, worst first, and the issues for the panel. Those cover a file such as `/.env` answering 200, IPs probing or trying passwords, and a site that can't see visitor IPs because every request seems to come from a proxy.
- `ProtectedRanges`: addresses that are never blocked or flagged.
  - These are Cloudflare, Laravel Forge and its health checks, private and reserved ranges, and the site's own config.
  - Published lists are fetched once a day.
  - A response that isn't a clean list of addresses is thrown away whole, and the copy bundled with the release is used instead.
- `Blocklist`: the blocklist and safelist and their safety rules.
  - It refuses blocks that would break the site: protected ranges, the admin's own IP, anything safelisted, ranges wider than /16 (IPv4) or /48 (IPv6), and more than 5,000 entries.
  - `prune()` drops expired entries and blocks that have since become protected or safelisted.
  - Connectors store entries through `EntryStore`, a database table, so every server of a site sees the same list.
- `Countries`: a rough country for each flagged IP.
  - Behind Cloudflare it uses the `CF-IPCountry` header the request already carries (`ClientIp::country()`), so there's no lookup at all.
  - Elsewhere it reads [DB-IP's free country file](https://db-ip.com/db/download/ip-to-country-lite) on the site: about 4MB, downloaded monthly by `update()`, CC BY 4.0. Panels showing these countries must credit DB-IP (`Countries::ATTRIBUTION`).
- `NginxBlocklist`: renders the `deny` file for nginx, plus the Cloudflare real-IP lines that must come before it. It writes the file atomically and only when the list changed.

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
