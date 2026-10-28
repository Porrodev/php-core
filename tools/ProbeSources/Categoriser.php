<?php

namespace Porro\Tools\ProbeSources;

use Porro\Core\Activity\Probes;

/**
 * A first guess at the Probes category a candidate path belongs in. Only
 * a suggestion for the reviewer: the path's shape wins, then the KEV
 * vendor, then the source's default.
 */
final class Categoriser
{
    /** Checked in order against the lower-cased path. */
    private const SHAPES = [
        '#(^|/)\.\.([/;\\\\]|\z)|%2e%2e|::\.\.|(^|/)(etc|proc|windows|winnt|boot|var/log|usr/local)/|(^|/)(win|boot|system)\.ini\z|^/@fs/#' => Probes::TRAVERSAL,
        '#(^|/)\.(git|svn|hg|bzr|cvs)(/|ignore|modules|attributes|\z)|gitlab-ci|travis\.ya?ml|bitbucket-pipelines#' => Probes::VCS,
        '#(^|/)wp-|xmlrpc\.php#' => Probes::WORDPRESS,
        '#phpmyadmin|adminer|(^|/)pma(/|\z)|phppgadmin|mysqladmin#' => Probes::DB_ADMIN,
        '#(^|/)(wso|alfa|c99|r57|b374k|xleet|priv8|indoxploit|leafmailer|gel4y)[^/]*\.ph#' => Probes::WEBSHELL,
        '#vendor/phpunit|_ignition|php-cgi|(^|/)cgi-bin/#' => Probes::EXPLOIT,
        '#web-inf|meta-inf|actuator|jolokia|wls-wsat|_async/|\.(action|do|jsp|jspx|jspws)\z|/manager/(html|text)#' => Probes::JAVA,
        '#phpinfo|_profiler|_debugbar|server-(status|info)|telescope|(^|/)[^/]*(debug|error)[^/]*\.log\z|\.log\z#' => Probes::DEBUG,
        '#(^|/)\.env|\.sql(\.|\z)|\.(bak|old|orig|swp|backup)\z|credentials|(^|/)\.ssh|id_(rsa|dsa|ecdsa|ed25519)|\.htpasswd|\.htdigest|tfstate|\.pem\z|\.key\z|(^|/)\.aws|(^|/)\.azure|(^|/)\.boto#' => Probes::SECRETS,
        '#/containers/json|/mlflow/|/_cat/|/_cluster/|/debug/pprof|meta-data|computemetadata|/nacos/|/v2/_catalog#' => Probes::INFRASTRUCTURE,
        '#(^|/)\.[^/]+|docker-compose|sftp|ftpconfig|filezilla|\.(ya?ml|ini|conf|cfg|xml|json|toml)\z#' => Probes::FILES,
    ];

    /** KEV vendorProject (lower case) when the path's shape says nothing. */
    private const VENDORS = [
        'apache' => Probes::JAVA, 'oracle' => Probes::JAVA, 'atlassian' => Probes::JAVA,
        'vmware' => Probes::JAVA, 'jenkins' => Probes::JAVA, 'liferay' => Probes::JAVA,
        'wordpress' => Probes::WORDPRESS, 'php' => Probes::EXPLOIT, 'laravel' => Probes::EXPLOIT,
        'docker' => Probes::INFRASTRUCTURE, 'kubernetes' => Probes::INFRASTRUCTURE, 'elastic' => Probes::INFRASTRUCTURE,
        'grafana' => Probes::INFRASTRUCTURE, 'gitlab' => Probes::INFRASTRUCTURE, 'jfrog' => Probes::INFRASTRUCTURE,
        'hashicorp' => Probes::INFRASTRUCTURE, 'databricks' => Probes::INFRASTRUCTURE, 'langflow' => Probes::INFRASTRUCTURE,
    ];

    /**
     * @param  string  $default  a Probes category for when nothing else fits
     */
    public static function suggest(string $path, string $default, ?string $vendor = null): string
    {
        $path = strtolower($path);

        foreach (self::SHAPES as $pattern => $category) {
            if (preg_match($pattern, $path)) {
                return $category;
            }
        }

        if ($vendor !== null) {
            $vendor = strtolower($vendor);

            foreach (self::VENDORS as $name => $category) {
                if (str_contains($vendor, $name)) {
                    return $category;
                }
            }
        }

        return $default;
    }

    /**
     * Every category a suggestion can name: exactly the Probes ones.
     *
     * @return list<string>
     */
    public static function categories(): array
    {
        return array_keys(Probes::PATTERNS);
    }
}
