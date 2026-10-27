<?php

namespace Porro\Core\Activity;

use Porro\Core\Health\Sources;

/**
 * AbuseIPDB's view of an IP: how sure it is the IP is abusive, and how
 * often it's been reported. Unlike every other lookup this sends the IP
 * to a third party, so it only runs when someone clicks, and the button
 * says so. Free keys allow 1,000 checks a day.
 */
final class AbuseIpdb
{
    public const URL = 'https://api.abuseipdb.com/api/v2/check';

    public function __construct(private readonly Sources $sources, private readonly string $key) {}

    /**
     * @return array{score: int, reports: int, last_reported: string|null, usage: string|null, isp: string|null}|null null when it couldn't be checked
     */
    public function check(string $ip): ?array
    {
        if (trim($this->key) === '' || ! Cidr::isValid($ip)) {
            return null;
        }

        return $this->sources->remember('abuseipdb:'.sha1($ip), IpDetails::TTL, function () use ($ip) {
            $data = $this->sources->json('GET', self::URL.'?'.http_build_query(['ipAddress' => $ip, 'maxAgeInDays' => 90]), ['Key' => $this->key])['data'] ?? null;

            if (! is_array($data) || ! isset($data['abuseConfidenceScore'])) {
                return null;
            }

            return [
                'score' => (int) $data['abuseConfidenceScore'],
                'reports' => (int) ($data['totalReports'] ?? 0),
                'last_reported' => is_string($data['lastReportedAt'] ?? null) ? $data['lastReportedAt'] : null,
                'usage' => is_string($data['usageType'] ?? null) ? $data['usageType'] : null,
                'isp' => is_string($data['isp'] ?? null) ? $data['isp'] : null,
            ];
        });
    }
}
