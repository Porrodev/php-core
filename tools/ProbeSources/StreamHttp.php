<?php

namespace Porro\Tools\ProbeSources;

/**
 * Plain PHP streams, HTTPS only, with a size cap per response. Sends
 * GITHUB_TOKEN to GitHub hosts only, which lifts the API's 60 requests an
 * hour limit in CI, and never across a redirect to another host.
 */
final class StreamHttp implements Http
{
    /**
     * The KEV feed is the biggest download at about 2 MB; CRS files and
     * nuclei templates are tens of KB.
     */
    public const MAX_BYTES = 8 * 1024 * 1024;

    public const MAX_REDIRECTS = 5;

    public const TOKEN_HOSTS = ['api.github.com', 'raw.githubusercontent.com'];

    public function __construct(
        private readonly ?string $githubToken = null,
        private readonly int $maxBytes = self::MAX_BYTES,
    ) {}

    public function get(string $url): ?string
    {
        $origin = self::host($url);

        for ($hop = 0; $hop <= self::MAX_REDIRECTS; $hop++) {
            if (! str_starts_with($url, 'https://')) {
                throw new \RuntimeException("Refusing to fetch {$url}: HTTPS only");
            }

            $headers = ['User-Agent: porro-php-core probe-sources', 'Accept: application/json, text/plain, */*'];

            if ($this->githubToken && self::sendsToken($url, $origin)) {
                $headers[] = 'Authorization: Bearer '.$this->githubToken;
            }

            $context = stream_context_create(['http' => [
                'header' => implode("\r\n", $headers),
                'timeout' => 30,
                'ignore_errors' => true,
                'follow_location' => 0,
            ]]);

            // One byte over the cap is enough to know it's too big.
            $body = @file_get_contents($url, false, $context, 0, $this->maxBytes + 1);
            [$status, $location] = self::parse($http_response_header ?? []);

            if ($status >= 300 && $status < 400 && $location !== null) {
                $url = self::resolve($url, $location);

                continue;
            }

            if ($status === 404) {
                return null;
            }

            if ($body === false || $status < 200 || $status >= 300) {
                throw new \RuntimeException("GET {$url} failed with HTTP {$status}");
            }

            if (strlen($body) > $this->maxBytes) {
                throw new \RuntimeException("GET {$url} is over the {$this->maxBytes} byte limit");
            }

            return $body;
        }

        throw new \RuntimeException('Too many redirects from '.$url);
    }

    /**
     * @param  list<string>  $headers
     * @return array{int, ?string}
     */
    private static function parse(array $headers): array
    {
        $status = 0;
        $location = null;

        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                $status = (int) $m[1];
            } elseif (preg_match('#^location:\s*(\S+)#i', $header, $m)) {
                $location = $m[1];
            }
        }

        return [$status, $location];
    }

    /**
     * The token goes only to the GitHub host first asked for, so a
     * redirect can't carry it anywhere else.
     */
    public static function sendsToken(string $url, string $origin): bool
    {
        $host = self::host($url);

        return $host === $origin && in_array($host, self::TOKEN_HOSTS, true);
    }

    private static function host(string $url): string
    {
        return strtolower((string) parse_url($url, PHP_URL_HOST));
    }

    /**
     * An absolute Location as is, or a root-relative one on the same host.
     */
    public static function resolve(string $from, string $location): string
    {
        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }

        if (str_starts_with($location, '/') && ! str_starts_with($location, '//')) {
            return 'https://'.self::host($from).$location;
        }

        throw new \RuntimeException("Refusing redirect from {$from} to {$location}");
    }
}
