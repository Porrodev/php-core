# Changelog

## 0.2.0 - 2026-10-23

- `Porro\Core\Health`: local site health checks for the connectors' control panel panel, with no Porro account needed: PHP and platform support dates (endoflife.date, cached daily, bundled fallback), security advisories in `composer.lock` (Packagist), key package updates, and the report-based checks Porro runs (debug mode, migrations, failed jobs, the queue, backups, health checks, cron).
- `PorroFindings` reads the site's open findings from Porro's new `GET /api/v1/findings`, signed with the site key.
- Requires `composer/semver`.

## 0.1.6

- Throttle for backup reports, client timeout, trigger names.
