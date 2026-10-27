<?php

namespace Porro\Core\Health;

use Closure;
use Porro\Core\Report;
use Throwable;

/**
 * Fetches the public data the local checks need (endoflife.date, Packagist)
 * through the connector's own cache, so a control panel page only waits
 * on the network once in a while. Failures are cached briefly too, so an
 * unreachable API never slows every page down.
 *
 * Responses over MAX_BYTES count as failures. The $http closure gets the
 * limit as its last argument, so it can stop reading there.
 */
final class Sources
{
    public const FAILURE_TTL = 600;

    /** Packagist's metadata for laravel/framework is about 1MB. */
    public const MAX_BYTES = 5_242_880;

    /**
     * @param  Closure(string $key): mixed  $get
     * @param  Closure(string $key, mixed $value, int $ttl): mixed  $put
     * @param  (Closure(string $method, string $url, array<string, string> $headers, string|null $body, int $timeout, int $maxBytes): array{0: int, 1: string})|null  $http
     */
    public function __construct(
        private readonly Closure $get,
        private readonly Closure $put,
        private readonly ?Closure $http = null,
        private readonly int $timeout = 5,
        private readonly int $maxBytes = self::MAX_BYTES,
    ) {}

    /**
     * The cached value, or $fetch's result stored for $ttl seconds. When
     * $fetch returns null (it failed), null is stored for FAILURE_TTL.
     *
     * @template T
     *
     * @param  Closure(): T  $fetch
     * @return T|null
     */
    public function remember(string $key, int $ttl, Closure $fetch): mixed
    {
        $key = 'porro:health:'.$key;

        try {
            $cached = ($this->get)($key);
        } catch (Throwable) {
            $cached = null;
        }

        if (is_array($cached) && array_key_exists('value', $cached)) {
            return $cached['value'];
        }

        try {
            $value = $fetch();
        } catch (Throwable) {
            $value = null;
        }

        try {
            ($this->put)($key, ['value' => $value], $value === null ? self::FAILURE_TTL : $ttl);
        } catch (Throwable) {
            // A broken cache only means fetching again next time.
        }

        return $value;
    }

    /**
     * Forgets everything cached under $key, e.g. after a "check again".
     */
    public function forget(string $key): void
    {
        try {
            ($this->put)('porro:health:'.$key, null, 1);
        } catch (Throwable) {
            //
        }
    }

    /**
     * A JSON response as an array, or null on any error.
     *
     * @param  array<string, string>  $headers
     * @return array<mixed>|null
     */
    public function json(string $method, string $url, array $headers = [], ?string $body = null): ?array
    {
        $response = $this->text($method, $url, $headers + ['Accept' => 'application/json'], $body);

        if ($response === null) {
            return null;
        }

        $data = json_decode($response, true);

        return is_array($data) ? $data : null;
    }

    /**
     * A successful response's body, or null on any error.
     *
     * @param  array<string, string>  $headers
     */
    public function text(string $method, string $url, array $headers = [], ?string $body = null): ?string
    {
        $headers += [
            'User-Agent' => 'porro-connector/'.(Report::installedVersion('porro/php-core') ?? 'dev').' (+https://porro.dev)',
        ];

        try {
            [$status, $response] = ($this->http ?? Closure::fromCallable([$this, 'request']))($method, $url, $headers, $body, $this->timeout, $this->maxBytes);
        } catch (Throwable) {
            return null;
        }

        if ($status < 200 || $status >= 300 || strlen($response) > $this->maxBytes) {
            return null;
        }

        return $response;
    }

    /**
     * @param  array<string, string>  $headers
     * @return array{0: int, 1: string}
     */
    private function request(string $method, string $url, array $headers, ?string $body, int $timeout, int $maxBytes): array
    {
        $context = stream_context_create(['http' => array_filter([
            'method' => $method,
            'header' => implode("\r\n", array_map(fn ($k, $v) => "{$k}: {$v}", array_keys($headers), $headers)),
            'content' => $body,
            'timeout' => $timeout,
            'ignore_errors' => true,
        ], fn ($value) => $value !== null)]);

        // One byte over the limit is enough to know it's too big.
        $response = @file_get_contents($url, false, $context, 0, $maxBytes + 1);

        if ($response === false) {
            return [0, ''];
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
