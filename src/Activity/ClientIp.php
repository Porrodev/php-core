<?php

namespace Porro\Core\Activity;

/**
 * The visitor's address. The framework's own value already respects the
 * site's trusted proxies; the only thing added here is Cloudflare, whose
 * header is believed only when the request really came from Cloudflare.
 * X-Forwarded-For is never read here: that is the framework's job.
 */
final class ClientIp
{
    /**
     * @param  array<string, string|list<string>>  $headers  any case
     */
    public static function resolve(string $frameworkIp, array $headers, ProtectedRanges $ranges): string
    {
        if (! $ranges->isCloudflare($frameworkIp)) {
            return $frameworkIp;
        }

        foreach ($headers as $name => $value) {
            if (strtolower($name) === 'cf-connecting-ip') {
                $value = trim(is_array($value) ? (string) ($value[0] ?? '') : $value);

                return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : $frameworkIp;
            }
        }

        return $frameworkIp;
    }
}
