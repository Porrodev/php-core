<?php

namespace Porro\Tools\ProbeSources;

/**
 * Plain PHP streams. Sends GITHUB_TOKEN to GitHub hosts only, which lifts
 * the API's 60 requests an hour limit in CI.
 */
final class StreamHttp implements Http
{
    public function __construct(private readonly ?string $githubToken = null) {}

    public function get(string $url): ?string
    {
        $headers = ['User-Agent: porro-php-core probe-sources', 'Accept: application/json, text/plain, */*'];
        $host = (string) parse_url($url, PHP_URL_HOST);

        if ($this->githubToken && in_array($host, ['api.github.com', 'raw.githubusercontent.com'], true)) {
            $headers[] = 'Authorization: Bearer '.$this->githubToken;
        }

        $context = stream_context_create(['http' => [
            'header' => implode("\r\n", $headers),
            'timeout' => 30,
            'ignore_errors' => true,
            'follow_location' => 1,
        ]]);

        $body = @file_get_contents($url, false, $context);
        $status = $this->status($http_response_header ?? []);

        if ($status === 404) {
            return null;
        }

        if ($body === false || $status < 200 || $status >= 300) {
            throw new \RuntimeException("GET {$url} failed with HTTP {$status}");
        }

        return $body;
    }

    /**
     * @param  list<string>  $headers
     */
    private function status(array $headers): int
    {
        $status = 0;

        // After redirects the last status line wins.
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                $status = (int) $m[1];
            }
        }

        return $status;
    }
}
