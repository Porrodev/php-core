<?php

namespace Porro\Core\Activity;

/**
 * Paths scanners ask for that no real visitor of a Laravel, Craft or
 * Statamic site ever does. A hit is a strong signal on its own, so every
 * pattern is a fixed shape anchored to where the target really lives,
 * never a generic word a content site might use as a slug. What's left
 * out on purpose is pinned by the "must not match" tests.
 */
final class Probes
{
    /** Reading the server's own files: ../, /etc/passwd, Vite's /@fs/. */
    public const TRAVERSAL = 'traversal';

    public const VCS = 'vcs';

    /** Credentials and dumps whose 2xx answer means they leaked. */
    public const SECRETS = 'secrets';

    /** Deploy and editor config: sought for secrets, but not exposure-checked. */
    public const FILES = 'files';

    /** Debug consoles and info leaks: phpinfo, profilers, logs. */
    public const DEBUG = 'debug';

    /** A shell someone else dropped earlier. */
    public const WEBSHELL = 'webshell';

    public const WORDPRESS = 'wordpress';

    public const DB_ADMIN = 'db_admin';

    /** Exposed service APIs: Docker, MLflow, Elasticsearch, cloud metadata. */
    public const INFRASTRUCTURE = 'infrastructure';

    /** VPNs, firewalls and enterprise servers with known exploited CVEs. */
    public const APPLIANCE = 'appliance';

    /** Spring, Tomcat, WebLogic, Confluence, and Log4Shell strings. */
    public const JAVA = 'java';

    /** PHP exploits: phpunit eval-stdin, Ignition, PHP-CGI. */
    public const EXPLOIT = 'exploit';

    /**
     * Longer paths are matched on their first whole segments up to this
     * length. nginx and Apache refuse request lines over 8 KB by default,
     * so a longer path never reaches the app to be recorded anyway.
     */
    public const MAX_LENGTH = 8192;

    /** Percent-decoding rounds, so %252e (double-encoded) still reads as ".". */
    public const DECODE_ROUNDS = 3;

    /** Checked in order; the first match names the category. */
    public const PATTERNS = [
        // %2e%2e survives three rounds of decoding only when someone
        // encoded it four times on purpose.
        self::TRAVERSAL => '#(^|/)\.\.(/|;|\\\\|\z)|\.\.\\\\|%2e%2e|\x00|(^|/)(etc/(passwd|shadow|group|hosts)|proc/(self|\d+)/(environ|cmdline|maps)|windows/win\.ini|win\.ini|boot\.ini)\z|^/@fs/#',
        self::VCS => '#(^|/)\.(git|svn|hg|bzr)(/|\z)|^/cvs/(entries|root)\z|^/(\.gitlab-ci\.yml|\.travis\.ya?ml|bitbucket-pipelines\.yml)\z#',
        self::SECRETS => '#(^|/)(\.env([./_~-].*)?|\.aws/(credentials|config)|\.ssh/.*|\.htpasswd|\.git-credentials|id_(rsa|dsa|ecdsa|ed25519)|[^/]*\.sql(\.(gz|zip|bz2|xz|7z|tar|tgz))?|terraform\.tfstate(\.backup)?|[^/]+\.php(\.(bak|old|orig|save|swp|swo|backup|copy|tmp|dist)|~)|\.[^/]+\.php\.sw[op])\z|^/(backups?|www|wwwroot|htdocs|public_html)\.(zip|rar|7z|tar|tar\.gz|tgz|tar\.bz2)\z#',
        self::FILES => '#^/(\.npmrc|\.yarnrc|\.pypirc|\.netrc|\.pgpass|\.my\.cnf|\.s3cfg|\.dockercfg|\.docker/config\.json|\.kube/config|\.vscode/sftp\.json|sftp-config\.json|\.ftpconfig|\.remote-sync\.json|ftp-sync\.json|filezilla\.xml|docker-compose([._-][a-z0-9_-]+)?\.ya?ml|\.terraform/.*|\.ds_store)\z#',
        self::DEBUG => '#^/((php_?info|phpinfo\d?|php-info)\.php|_profiler(/.*)?|_wdt/.*|app_dev\.php(/.*)?|_debugbar/open|server-(status|info)|storage/logs/[^/]+\.log|telescope(/.*)?)\z#',
        self::WEBSHELL => '#(^|/)(wso\d*|alfa(-?rex)?|c99|r57|b374k|xleet|priv8|indoxploit|leafmailer|marijuana|gel4y|tinyfilemanager)\.(php\d?|phtml)\z|^/\.well-known/(acme-challenge|pki-validation)/[^/]*\.(php\d?|phtml|phar)\z#',
        // Images and PDFs under wp-content/uploads are old backlinks on a
        // site that used to be WordPress, not probes.
        self::WORDPRESS => '#(^|/)(wp-login\.php|xmlrpc\.php|wp-admin(/.*)?|wp-includes/.*|wp-content/(?!uploads/.*\.(jpe?g|png|gif|webp|avif|svg|pdf|mp4)\z).*)\z#',
        self::DB_ADMIN => '#^/(phpmyadmin(\d[\d.]*|-[\d.]+(-[a-z]+)?)?|pma|myadmin|mysqladmin|phppgadmin|adminer(-[\d.]+(-[a-z]+)?)?(\.php)?)(/.*)?\z|^/(xampp|admin|db|sql|mysql)/(phpmyadmin|pma|adminer(\.php)?)(/.*)?\z#',
        // Exact service shapes only: generic words like /v1/models, /api/tags
        // or /metrics are real routes on plenty of sites.
        self::INFRASTRUCTURE => '#^/(v1\.\d+/)?(containers|images)/json\z|^/(ajax-)?api/2\.0/mlflow/|^/v2/_catalog\z|^/(_cat/(indices|nodes|health)|_cluster/(health|settings|state)|_all/_search)\z|^/debug/pprof(/.*)?\z|^/latest/meta-data(/.*)?\z|^/computemetadata/v1(/.*)?\z|^/nacos/v1/(auth|cs|ns|console)/#',
        self::APPLIANCE => '#^/(dana-na|dana-ws|dana-cached)/|^/remote/(logincheck|fgt_lang)|^/(global-protect/(login|getconfig|portal)|ssl-vpn/hipreport\.esp)|^/\+csco[el]\+/|^/(mgmt/tm|tmui)/|^/clients/mycrl\z|^/p/u/doauthentication\.do\z|^/vpns/|^/setupwizard\.aspx|^/webinterface/function|^/developmentserver/metadatauploader\z|^/_layouts/15/toolpane\.aspx|^/moveitisapi/moveitisapi\.dll|^/(hnap1|gponform/diag_form|boaform/.*|goform/(formlogin|setmacfilter|setusbshare|websgetcfg)[^/]*)\z#',
        self::JAVA => '#(^|/)(web-inf|meta-inf)(/|\z)|^/actuator(/.*)?\z|^/(manager/(html|text|status)|host-manager/.*|jolokia(/.*)?|wls-wsat/.*|_async/.*)\z|^/(server-info|json/setup-restore(-local)?)\.action\z|\$\{(jndi|::-j|lower:j)#',
        self::EXPLOIT => '#(^|/)(vendor/phpunit/.*|cgi-bin/.*|_ignition/(execute-solution|update-config))\z|^/php-cgi/php-cgi\.exe\z#',
    ];

    /** Categories that leak something when the site answers 2xx. */
    public const EXPOSING = [self::SECRETS, self::VCS];

    /** What each category's probes were after, in words, for the IP page. */
    public const LABELS = [
        self::TRAVERSAL => 'Server files, by path traversal',
        self::VCS => 'Version control (.git)',
        self::SECRETS => 'Secrets: .env, keys, database dumps',
        self::FILES => 'Deploy and editor config',
        self::DEBUG => 'Debug pages and logs',
        self::WEBSHELL => 'Web shells left by others',
        self::WORDPRESS => 'WordPress',
        self::DB_ADMIN => 'Database admin tools',
        self::INFRASTRUCTURE => 'Exposed services: Docker, MLflow, cloud metadata',
        self::APPLIANCE => 'VPNs, firewalls and enterprise servers',
        self::JAVA => 'Java servers',
        self::EXPLOIT => 'Known PHP exploits',
    ];

    /** @var list<string> */
    private readonly array $served;

    /**
     * @param  list<string>  $served  path prefixes the app really serves (e.g. "/telescope"), never flagged
     */
    public function __construct(
        private readonly string $platform = '',
        array $served = [],
    ) {
        $this->served = array_values(array_map(fn (string $p) => rtrim(self::normalise($p), '/'), $served));
    }

    /**
     * The probe category for a request path, or null.
     */
    public function match(string $path): ?string
    {
        $path = self::normalise($path);

        foreach ($this->served as $prefix) {
            if ($path === $prefix || str_starts_with($path, $prefix.'/')) {
                return null;
            }
        }

        if (strlen($path) > self::MAX_LENGTH) {
            // Whole segments only, so "\z" can't land inside a cut one and
            // turn "x.sqlite…" into "x.sql".
            $path = substr($path, 0, (int) strrpos(substr($path, 0, self::MAX_LENGTH + 1), '/')).'/';
        }

        return $this->categorise($path);
    }

    /**
     * The first category whose pattern matches an already normalised path.
     */
    private function categorise(string $path): ?string
    {
        foreach (self::PATTERNS as $category => $pattern) {
            if ($category === self::WORDPRESS && $this->platform === 'wordpress') {
                continue;
            }

            // A regex error must never pass quietly as "not a probe".
            if (($hit = preg_match($pattern, $path)) === false) {
                throw new \RuntimeException("Probe pattern {$category} failed: ".preg_last_error_msg());
            }

            if ($hit) {
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
     * Lower case, query and fragment stripped, percent-decoded up to three
     * times, slashes collapsed, so "/%2Eenv?x", "//.ENV" and "/%252eenv"
     * count the same as "/.env". Only used for matching: backslashes,
     * trailing dots and ";" parameters are left as they are, and the
     * patterns look for them.
     */
    public static function normalise(string $path): string
    {
        $path = substr($path, 0, strcspn($path, '?#'));

        for ($i = 0; $i < self::DECODE_ROUNDS && str_contains($path, '%'); $i++) {
            $decoded = rawurldecode($path);

            if ($decoded === $path) {
                break;
            }

            $path = $decoded;
        }

        return (string) preg_replace('#/+#', '/', '/'.ltrim(strtolower($path), '/'));
    }
}
