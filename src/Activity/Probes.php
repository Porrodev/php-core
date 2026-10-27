<?php

namespace Porro\Core\Activity;

/**
 * Paths scanners ask for that no real visitor of a Laravel, Craft or
 * Statamic site ever does. A hit is a strong signal on its own.
 */
final class Probes
{
    public const SECRETS = 'secrets';

    public const VCS = 'vcs';

    public const WORDPRESS = 'wordpress';

    public const DB_ADMIN = 'db_admin';

    public const EXPLOIT = 'exploit';

    /** Checked in order; the first match names the category. */
    public const PATTERNS = [
        self::VCS => '#(^|/)\.(git|svn|hg)(/|$)#',
        self::SECRETS => '#(^|/)(\.env([./_-].*)?|\.aws/credentials|\.ssh/.*|\.htpasswd|id_[rd]sa|[^/]*\.sql(\.gz|\.zip)?|backup\.(zip|tar|tar\.gz|tgz|sql)|(config|wp-config|database)\.php\.(bak|old|orig|save|swp|txt|~))$#',
        self::WORDPRESS => '#(^|/)(wp-login\.php|xmlrpc\.php|wp-admin(/.*)?|wp-content/.*|wp-includes/.*)$#',
        self::DB_ADMIN => '#^/(phpmyadmin[^/]*|pma|myadmin|adminer(-[\d.]+)?(\.php)?)(/.*)?$#',
        self::EXPLOIT => '#(^|/)(vendor/phpunit/.*|cgi-bin/.*|_ignition/execute-solution|actuator(/.*)?|boaform/.*|telescope(/.*)?)$#',
    ];

    /** Categories that leak something when the site answers 2xx. */
    public const EXPOSING = [self::SECRETS, self::VCS];

    /**
     * @param  list<string>  $served  path prefixes the app really serves (e.g. "/telescope"), never flagged
     */
    public function __construct(
        private readonly string $platform = '',
        private readonly array $served = [],
    ) {}

    /**
     * The probe category for a request path, or null.
     */
    public function match(string $path): ?string
    {
        $path = self::normalise($path);

        foreach ($this->served as $prefix) {
            $prefix = self::normalise($prefix);

            if ($path === $prefix || str_starts_with($path, rtrim($prefix, '/').'/')) {
                return null;
            }
        }

        foreach (self::PATTERNS as $category => $pattern) {
            if ($category === self::WORDPRESS && $this->platform === 'wordpress') {
                continue;
            }

            if (preg_match($pattern, $path)) {
                return $category;
            }
        }

        return null;
    }

    /**
     * True when a 2xx answer to this probe means a file is public.
     */
    public static function exposes(?string $category): bool
    {
        return in_array($category, self::EXPOSING, true);
    }

    /**
     * Lower case, query stripped, percent-decoded, slashes collapsed, so
     * "/%2Eenv?x" and "//.ENV" count the same as "/.env".
     */
    public static function normalise(string $path): string
    {
        $path = substr($path, 0, strcspn($path, '?#'));
        $path = strtolower(rawurldecode($path));
        $path = preg_replace('#/+#', '/', '/'.ltrim($path, '/'));

        return $path;
    }
}
