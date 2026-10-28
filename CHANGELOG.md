# Changelog

## Unreleased

- `Cloudflare::verify()` accepts account-owned tokens. Cloudflare's user endpoint calls them invalid, so it checks them again at their account's endpoint.
- An unknown token now gets its own message: check it's the token itself, not its ID or the Global API Key. Quotes and spaces pasted around the token are ignored.
- The permissions are named as Cloudflare's dashboard shows them: Zone WAF Rules: Edit and Zone: Read on the domain, Account Rule Lists: Edit on the account (`Cloudflare::PERMISSIONS`).

## 0.3.1 - 2026-10-28

- `NginxBlocklist::stablePath()`: a path nginx can keep using across zero-downtime deploys. It follows a shared-storage symlink to its real path, or goes through the `current` symlink when the folder lives in the release.

## 0.3.0 - 2026-10-27

- `Porro\Core\Activity`, for the connectors' suspicious activity and blocking panels. Everything stays on the site.
  - `ClientIp` resolves the visitor's address.
  - `Probes` matches scanner paths.
  - `Recorder` counts suspicious requests in the cache and summarises them. Its issues are `exposed_file`, `suspicious_activity` and `client_ip_unknown`.
  - `ProtectedRanges` covers Cloudflare, Forge and its health checks, and reserved ranges, fetched daily with a bundled fallback.
  - `Blocklist` holds the blocklist and safelist and enforces the safety rules, through an `EntryStore` the connector provides.
  - `Countries` gives a rough country for flagged IPs. It uses Cloudflare's `CF-IPCountry` when present, otherwise DB-IP's free country file read on the site. `Recorder::record()` takes the country Cloudflare sent.
  - `Cloudflare` blocks at Cloudflare's edge, through one account IP List (`porro_blocklist`) and one custom rule on the zone.
    - Each site syncs only items carrying its own comment prefix, so many sites can share one account's list.
    - The rule is added next to the zone's own custom rules and never replaces them.
  - `NginxStatus` checks a server's nginx setup by looking, never by running anything.
    - It reports whether the deny file is written and whether site config includes it, read from `/etc/nginx/sites-enabled`, `conf.d` and `forge-conf`.
    - It also reports whether the reload job has reloaded nginx since the last change.
    - `reloadJob()` gives the root scheduler command.
  - `IpDetails` says who's behind a flagged IP, from sources that send it nowhere new:
    - Cloudflare Intel or Radar, through the connector
    - DB-IP country
    - the Tor exit list and Spamhaus DROP, downloaded whole
    - reverse DNS confirmed by a forward lookup, which spots fake Googlebots and research scanners

    Results are cached a day. `Cloudflare::intel()` and `radar()` feed it.
  - `AbuseIpdb` checks one IP on request. It's the only lookup that sends the IP to a third party.
  - `Recorder` keeps each flagged IP's last user agent.
  - `Ranking` orders flagged IPs by what's known about them.
    - **Multipliers:** Spamhaus ×3, Tor ×1.5, a fake crawler ×1.5, Cloudflare Botnet or Anonymizer ×2, and a hosting network trying passwords ×1.5.
    - **Scanners:** research scanners go last.
    - **Inputs:** `IpDetails::known()` feeds it from the Tor and Spamhaus lists and any cached lookup, without waiting on the network.
  - `NginxBlocklist` renders the nginx deny file and real-IP lines. `render()` can carry Cloudflare's real-IP lines in the deny file itself, so a site behind Cloudflare needs one include and the ranges stay current. `NginxStatus` counts real-IP lines found there.
  - `ProtectedRanges` also protects Google's and Bing's verified search crawlers (their published lists, fetched daily as JSON with bundled copies; never Google Cloud or user-triggered fetchers). `about()` explains each list, where it comes from and its ranges. Forge, its health checks and the crawlers can be switched off; Cloudflare and private ranges can't.
- Requires `maxmind-db/reader`.
- `Sources::text()` fetches a plain-text response. `json()` now uses it.

## 0.2.1

- Signatures now cover the method and path (`connector-v1\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{sha256 of body}`), so a report's signature can't be used to read findings or the other way round. `SiteKey::headers()` takes the method and path; it defaults to `POST /api/v1/reports`. Porro still accepts the old signature for reports, but reading findings needs this version.
- Site health only leaves out a local issue when Porro has an open finding of the same kind, rather than every kind Porro could raise.
- `PorroFindings` caches per Porro URL and key (`SiteKey::id()`), so changing either never shows the old answer.
- `Sources` treats responses over 5MB (`Sources::MAX_BYTES`) as failures and passes the limit to the HTTP closure, so it can stop reading.
- Advisory titles are shortened without needing `ext-mbstring`.
- `EndOfLife::forget()`, `Advisories::forget()` and `Updates::forget()`, for a "check again" that fetches everything again.
- `PorroFindings` skips findings that aren't plain values instead of failing on them.
- `Porro\Core\Database::describe()` and `Report::database()`: the site's database engine, version, whether it's on the same machine and whether it's a known managed service, so Porro can flag an end-of-life MySQL, MariaDB or PostgreSQL. The host, database name, user and credentials are never sent.

## 0.2.0 - 2026-10-23

- `Porro\Core\Health`: local site health checks for the connectors' control panel panel, with no Porro account needed: PHP and platform support dates (endoflife.date, cached daily, bundled fallback), security advisories in `composer.lock` (Packagist), key package updates, and the report-based checks Porro runs (debug mode, migrations, failed jobs, the queue, backups, health checks, cron).
- `PorroFindings` reads the site's open findings from Porro's new `GET /api/v1/findings`, signed with the site key.
- Requires `composer/semver`.

## 0.1.6

- Throttle for backup reports, client timeout, trigger names.
