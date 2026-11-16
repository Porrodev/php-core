<?php

namespace Porro\Core;

use Closure;
use InvalidArgumentException;

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
        // Seconds; backup reports use a short one so they never hold anything up.
        private readonly int $timeout = 15,
    ) {
        if ($key->siteId === null) {
            throw new InvalidArgumentException('This key has no site yet, so it can’t send reports. Finish connecting first.');
        }
    }

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

    /**
     * Tells Porro this site has been disconnected. Porro switches the key
     * off with this call, so the caller deletes its copy afterwards,
     * whatever the answer: the person asked for the site to stop reporting.
     */
    public function disconnect(): Result
    {
        return $this->post('/api/v1/disconnect', '{}');
    }

    private function deliver(Report $report): Result
    {
        return $this->post('/api/v1/reports', $report->toJson());
    }

    private function post(string $path, string $body): Result
    {
        $url = rtrim($this->baseUrl, '/').$path;
        $attempt = 0;

        while (true) {
            $headers = $this->key->headers($body, null, 'POST', $path) + Transport::jsonHeaders();

            [$status, $response] = ($this->transport ?? Transport::stream($this->timeout))($url, $headers, $body);
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
}
