# Changelog

## 0.2.1

- Signatures now cover the method and path (`connector-v1\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{sha256 of body}`), so a report's signature can't be used to read findings or the other way round. `SiteKey::headers()` takes the method and path; it defaults to `POST /api/v1/reports`. Porro still accepts the old signature for reports, but reading findings needs this version.
- Site health only leaves out a local issue when Porro has an open finding of the same kind, rather than every kind Porro could raise.
- `PorroFindings` caches per Porro URL and key (`SiteKey::id()`), so changing either never shows the old answer.
- `Sources` treats responses over 5MB (`Sources::MAX_BYTES`) as failures and passes the limit to the HTTP closure, so it can stop reading.
- Advisory titles are shortened without needing `ext-mbstring`.

## 0.2.0 - 2026-10-23

- `Porro\Core\Health`: local site health checks for the connectors' control panel panel, with no Porro account needed: PHP and platform support dates (endoflife.date, cached daily, bundled fallback), security advisories in `composer.lock` (Packagist), key package updates, and the report-based checks Porro runs (debug mode, migrations, failed jobs, the queue, backups, health checks, cron).
- `PorroFindings` reads the site's open findings from Porro's new `GET /api/v1/findings`, signed with the site key.
- Requires `composer/semver`.

## 0.1.6

- Throttle for backup reports, client timeout, trigger names.
