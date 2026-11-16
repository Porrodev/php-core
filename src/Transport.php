<?php

namespace Porro\Core;

use Closure;

/**
 * The default way out: a plain HTTP POST with PHP's own streams, for
 * sites with no HTTP client of their own. Connectors usually pass their
 * framework's client instead.
 */
final class Transport
{
    /**
     * @return Closure(string $url, array<string, string> $headers, string $body): array{0: int, 1: string}
     */
    public static function stream(int $timeout = 15): Closure
    {
        return static function (string $url, array $headers, string $body) use ($timeout): array {
            $context = stream_context_create(['http' => [
                'method' => 'POST',
                'header' => implode("\r\n", array_map(fn ($k, $v) => "{$k}: {$v}", array_keys($headers), $headers)),
                'content' => $body,
                'timeout' => $timeout,
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
        };
    }

    /**
     * @return array<string, string>
     */
    public static function jsonHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'User-Agent' => 'porro-connector/'.(Report::installedVersion('porro/php-core') ?? 'dev'),
        ];
    }
}
