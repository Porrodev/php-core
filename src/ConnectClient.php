<?php

namespace Porro\Core;

use Closure;
use InvalidArgumentException;
use SensitiveParameter;
use Throwable;

/**
 * Connecting a site from its own control panel, with no key to copy.
 *
 * 1. start(): the site makes a key (SiteKey::generate()) and asks to
 *    connect. Porro answers with a page to send the person's browser to.
 * 2. Someone signed in to Porro approves it there. Their browser comes back
 *    to the site's return URL with porro_request, porro_grant and porro_next.
 * 3. complete(): the site finishes it with the grant. Only then is the key
 *    the site's; Porro answers with the site's id, which makes the site key.
 *
 * Both calls are signed with the new key, without X-Porro-Site. Only ever
 * outbound requests to Porro; nothing connects back in.
 */
final class ConnectClient
{
    private const PATH = '/api/v1/connect';

    /**
     * @param  (Closure(string $url, array<string, string> $headers, string $body): array{0: int, 1: string})|null  $transport
     */
    public function __construct(
        private readonly string $baseUrl = Client::DEFAULT_URL,
        private readonly ?Closure $transport = null,
        private readonly int $timeout = 15,
    ) {}

    /**
     * Ask to connect. The return URL must be on the site's own address,
     * over https, with no port, sign-in details or fragment.
     *
     * @param  array{name: string, version: string}  $connector
     * @param  array{name?: string|null, version?: string|null, environment?: string|null}  $platform
     *
     * @throws ConnectError
     */
    public function start(#[SensitiveParameter] SiteKey $key, string $address, string $returnUrl, array $connector, array $platform = [], ?string $phpVersion = null): ConnectRequest
    {
        $body = (string) json_encode([
            'address' => $address,
            'return_url' => $returnUrl,
            'public_key' => $key->publicKey(),
            'connector' => ['name' => $connector['name'], 'version' => $connector['version']],
            'platform' => [
                'name' => $platform['name'] ?? null,
                'version' => $platform['version'] ?? null,
                'environment' => $platform['environment'] ?? null,
            ],
            'php' => ['version' => $phpVersion ?? PHP_VERSION],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Asking twice is harmless (the first request just expires), so a
        // network or server error gets one more try.
        [$status, $response] = $this->post($key, self::PATH, $body);

        if ($status === 0 || $status >= 500) {
            usleep(300_000);
            [$status, $response] = $this->post($key, self::PATH, $body);
        }

        $json = $this->answer($status, $response);
        $id = $json['id'] ?? null;
        $approve = $json['approve_url'] ?? null;

        // The browser is only ever sent to the Porro this site is set up for.
        if (! is_string($id) || ! self::isId($id) || ! is_string($approve) || ! $this->onPorro($approve)) {
            throw new ConnectError(ConnectError::UNEXPECTED, $status);
        }

        return new ConnectRequest($id, $approve, is_string($json['expires_at'] ?? null) ? $json['expires_at'] : null);
    }

    /**
     * Finish it with the grant the browser brought back. Never retried: the
     * grant works once.
     *
     * @throws ConnectError
     */
    public function complete(#[SensitiveParameter] SiteKey $key, string $id, #[SensitiveParameter] string $grant): ConnectResult
    {
        // Both come from the browser's address bar.
        if (! self::isId($id)) {
            throw new ConnectError(ConnectError::NOT_FOUND);
        }

        if ($grant === '' || strlen($grant) > 200) {
            throw new ConnectError(ConnectError::GRANT);
        }

        [$status, $response] = $this->post($key, self::PATH.'/'.strtolower($id).'/complete', (string) json_encode(['grant' => $grant]));
        $json = $this->answer($status, $response, completing: true);

        try {
            $key = $key->withSite(is_string($json['site'] ?? null) ? $json['site'] : '');
        } catch (InvalidArgumentException) {
            throw new ConnectError(ConnectError::UNEXPECTED, $status);
        }

        return new ConnectResult(
            $key,
            is_string($json['host'] ?? null) ? $json['host'] : null,
            is_string($json['workspace'] ?? null) ? $json['workspace'] : null,
        );
    }

    /**
     * Whether a URL is on the Porro this site is set up for: the same
     * scheme, host and port, with no sign-in details. For approve_url, and
     * for porro_next before the browser is sent there.
     */
    public function onPorro(string $url): bool
    {
        $base = parse_url(rtrim($this->baseUrl, '/'));
        $parts = filter_var($url, FILTER_VALIDATE_URL) === false ? false : parse_url($url);

        if (! is_array($base) || ! is_array($parts) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        return in_array(strtolower($parts['scheme'] ?? ''), ['https', 'http'], true)
            && strtolower($parts['scheme'] ?? '') === strtolower($base['scheme'] ?? '')
            && strtolower($parts['host'] ?? '') === strtolower($base['host'] ?? '')
            && ($parts['port'] ?? null) === ($base['port'] ?? null);
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function post(#[SensitiveParameter] SiteKey $key, string $path, #[SensitiveParameter] string $body): array
    {
        $headers = $key->headers($body, null, 'POST', $path) + Transport::jsonHeaders();

        // Signed as a key with no site, whatever key was passed.
        unset($headers['X-Porro-Site']);

        // A transport that throws counts as not reaching Porro. Its
        // exception is dropped, not chained: its trace holds the body
        // (the grant, when finishing) and the signature headers.
        try {
            $answer = ($this->transport ?? Transport::stream($this->timeout))(rtrim($this->baseUrl, '/').$path, $headers, $body);
        } catch (Throwable) {
            return [0, ''];
        }

        return [(int) ($answer[0] ?? 0), (string) ($answer[1] ?? '')];
    }

    /**
     * @return array<mixed>
     *
     * @throws ConnectError
     */
    private function answer(int $status, string $response, bool $completing = false): array
    {
        if ($status < 200 || $status >= 300) {
            throw ConnectError::fromResponse($status, $response, $completing);
        }

        $json = json_decode($response, true);

        if (! is_array($json) || ($json['ok'] ?? false) !== true) {
            throw new ConnectError(ConnectError::UNEXPECTED, $status);
        }

        return $json;
    }

    private static function isId(string $id): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id) === 1;
    }
}
