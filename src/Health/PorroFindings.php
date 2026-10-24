<?php

namespace Porro\Core\Health;

use Porro\Core\Client;
use Porro\Core\SiteKey;

/**
 * The site's open findings in Porro (uptime, SSL, domain, the server's
 * OS and packages, advisories…), read with the same site key the
 * connector reports with. Cached for a few minutes, so the control panel
 * never asks Porro more than that, whoever is looking.
 */
final class PorroFindings
{
    public const TTL = 300;

    public function __construct(
        private readonly Sources $sources,
        private readonly SiteKey $key,
        private readonly string $baseUrl = Client::DEFAULT_URL,
    ) {}

    /**
     * @return array{ok: bool, findings: list<Issue>, site_url: string|null, error: string|null}
     */
    public function fetch(): array
    {
        $data = $this->sources->remember('porro:'.$this->key->siteId, self::TTL, function () {
            $url = rtrim($this->baseUrl, '/').'/api/v1/findings';
            // A GET has no body; the signature covers the empty one, and
            // the nonce and timestamp keep it from being replayed.
            $data = $this->sources->json('GET', $url, $this->key->headers(''));

            return is_array($data) && ($data['ok'] ?? false) === true && is_array($data['findings'] ?? null) ? $data : null;
        });

        if (! is_array($data)) {
            return ['ok' => false, 'findings' => [], 'site_url' => null, 'error' => 'Couldn’t reach Porro just now.'];
        }

        $findings = [];

        foreach ($data['findings'] as $finding) {
            if (! is_array($finding) || ! isset($finding['title'])) {
                continue;
            }

            $findings[] = new Issue(
                (string) ($finding['kind'] ?? ''),
                Issue::severityForRank((int) ($finding['rank'] ?? 6)),
                (string) $finding['title'],
                isset($finding['detail']) ? (string) $finding['detail'] : null,
                null,
                self::link($finding['url'] ?? null),
                Issue::SOURCE_PORRO,
                ($finding['scope'] ?? null) === 'server' ? 'server' : 'site',
                (bool) ($finding['acknowledged'] ?? false),
            );
        }

        return [
            'ok' => true,
            'findings' => Issue::sort($findings),
            'site_url' => self::link($data['site']['url'] ?? null),
            'error' => null,
        ];
    }

    public function forget(): void
    {
        $this->sources->forget('porro:'.$this->key->siteId);
    }

    /**
     * Only https links (http for a local Porro) make it into the panel.
     */
    private static function link(mixed $url): ?string
    {
        return is_string($url) && preg_match('#^https?://#i', $url) ? $url : null;
    }
}
