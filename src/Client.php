<?php

namespace Porro\Core;

use Closure;

/**
 * Signs and sends a report to Porro. Only ever makes outbound HTTPS
 * requests; nothing connects back in.
 */
final class Client
{
    public const DEFAULT_URL = 'https://app.porro.dev';

    /**
     * @param  (Closure(string $url, array<string, string> $headers, string $body): array{0: int, 1: string})|null  $transport
     */
    public function __construct(
        private readonly SiteKey $key,
        private readonly string $baseUrl = self::DEFAULT_URL,
        private readonly ?Closure $transport = null,
        private readonly int $retries = 2,
    ) {}

    public function send(Report $report): Result
    {
        $result = $this->deliver($report);

        // Porro doesn't have this server's package list yet (it changed, or
        // it's a new server): send the report again, once, with the list.
        if ($result->ok && $result->needSystemPackages && ! $report->includesSystemPackages() && $report->systemPackagesHash() !== null) {
            $report->systemPackages(true);
            $result = $this->deliver($report);
        }

        return $result;
    }

    private function deliver(Report $report): Result
    {
        $body = $report->toJson();
        $url = rtrim($this->baseUrl, '/').'/api/v1/reports';
        $attempt = 0;

        while (true) {
            $headers = $this->key->headers($body) + [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'User-Agent' => 'porro-connector/'.(Report::installedVersion('porro/php-core') ?? 'dev'),
            ];

            [$status, $response] = ($this->transport ?? Closure::fromCallable([$this, 'post']))($url, $headers, $body);
            $json = json_decode($response, true);

            if ($status >= 200 && $status < 300) {
                return new Result(
                    true,
                    $status,
                    (bool) ($json['need_lock'] ?? false),
                    needNpmLock: (bool) ($json['need_npm_lock'] ?? false),
                    needSystemPackages: (bool) ($json['need_system_packages'] ?? false),
                );
            }

            // Retry network errors and server errors, never rejections.
            if (($status === 0 || $status >= 500) && $attempt < $this->retries) {
                $attempt++;
                usleep(250_000 * 2 ** $attempt);

                continue;
            }

            return new Result(false, $status, false, is_array($json) && isset($json['error']) ? (string) $json['error'] : ($status === 0 ? $response : "HTTP {$status}"));
        }
    }

    /**
     * @param  array<string, string>  $headers
     * @return array{0: int, 1: string}
     */
    private function post(string $url, array $headers, string $body): array
    {
        $context = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => implode("\r\n", array_map(fn ($k, $v) => "{$k}: {$v}", array_keys($headers), $headers)),
            'content' => $body,
            'timeout' => 15,
            'ignore_errors' => true,
        ]]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            return [0, error_get_last()['message'] ?? 'Could not reach Porro'];
        }

        $status = 0;

        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
            }
        }

        return [$status, $response];
    }
}
