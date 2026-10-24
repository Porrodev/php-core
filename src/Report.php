<?php

namespace Porro\Core;

use Composer\InstalledVersions;

/**
 * A connector report (schema 1). Facts about the software and the server
 * it runs on only: never content, customer data, environment values or
 * secrets.
 */
final class Report
{
    public const TRIGGER_CONNECT = 'connect';

    // Cron, or the Laravel scheduler.
    public const TRIGGER_SCHEDULE = 'schedule';

    public const TRIGGER_MANUAL = 'manual';

    public const TRIGGER_DEPLOY = 'deploy';

    // A control panel visit, as a backup for a missing cron line.
    public const TRIGGER_CP = 'cp';

    // Straight after something changed: a plugin or the platform updated.
    public const TRIGGER_EVENT = 'event';

    /** @var array<string, mixed> */
    private array $data;

    /**
     * The server's installed packages, kept out of the report until Porro
     * asks for them: it already has the list whenever the hash matches.
     *
     * @var list<array<string, string>>|null
     */
    private ?array $systemPackages = null;

    public function __construct(string $connector, string $platform)
    {
        $this->data = [
            'schema' => 1,
            'connector' => ['name' => $connector, 'version' => self::installedVersion($connector) ?? 'dev'],
            'sent_at' => gmdate('c'),
            'php' => ['version' => PHP_VERSION],
            'platform' => ['name' => $platform, 'version' => null, 'environment' => null],
            'layers' => [],
            'health' => [],
            'lock' => null,
            'system' => null,
        ];

        $this->system(System::read());
    }

    /**
     * Replace what System::read() found, e.g. in tests. The package list
     * is held back until systemPackages(true).
     *
     * @param  array<string, mixed>|null  $system
     */
    public function system(?array $system): self
    {
        $this->systemPackages = is_array($system['packages'] ?? null) ? $system['packages'] : null;

        if (is_array($system) && array_key_exists('packages', $system)) {
            $system['packages'] = null;
        }

        $this->data['system'] = $system;

        return $this;
    }

    /**
     * Send the server's package list with the report, or just its hash.
     */
    public function systemPackages(bool $include): self
    {
        if (is_array($this->data['system'] ?? null) && $this->systemPackages !== null) {
            $this->data['system']['packages'] = $include ? $this->systemPackages : null;
        }

        return $this;
    }

    public function systemPackagesHash(): ?string
    {
        return $this->data['system']['packages_hash'] ?? null;
    }

    public function includesSystemPackages(): bool
    {
        return is_array($this->data['system']['packages'] ?? null);
    }

    /**
     * What sent this report: one of the TRIGGER_ constants. Lets Porro
     * tell whether cron is set up, and running.
     */
    public function trigger(string $trigger): self
    {
        $this->data['trigger'] = $trigger;

        return $this;
    }

    public function platform(?string $version, ?string $environment): self
    {
        $this->data['platform']['version'] = $version;
        $this->data['platform']['environment'] = $environment;

        return $this;
    }

    /**
     * Something layered on the platform, e.g. Filament or Statamic.
     *
     * @param  array<string, mixed>  $data
     */
    public function layer(string $name, ?string $version, array $data = []): self
    {
        $this->data['layers'][] = ['name' => $name, 'version' => $version, 'data' => $data];

        return $this;
    }

    public function health(string $key, mixed $value): self
    {
        $this->data['health'][$key] = $value;

        return $this;
    }

    /**
     * @param  array{name: string, status: string, summary?: string|null}  $check
     */
    public function check(array $check): self
    {
        $this->data['health']['checks'][] = $check;

        return $this;
    }

    /**
     * Always send the hash; send the package list only when asked to.
     */
    public function lock(?LockFile $lock, bool $includePackages): self
    {
        $this->data['lock'] = $lock ? [
            'hash' => $lock->hash,
            'packages' => $includePackages ? $lock->packages : null,
        ] : null;

        return $this;
    }

    public function lockHash(): ?string
    {
        return $this->data['lock']['hash'] ?? null;
    }

    public function includesPackages(): bool
    {
        return is_array($this->data['lock']['packages'] ?? null);
    }

    /**
     * The site's npm lock file, as lock() does for composer.lock. Null says
     * the site has none, so Porro can forget npm packages it had.
     */
    public function npmLock(?NpmLockFile $lock, bool $includePackages): self
    {
        $this->data['npm_lock'] = $lock ? [
            'hash' => $lock->hash,
            'packages' => $includePackages ? $lock->packages : null,
        ] : null;

        return $this;
    }

    public function npmLockHash(): ?string
    {
        return $this->data['npm_lock']['hash'] ?? null;
    }

    public function includesNpmPackages(): bool
    {
        return is_array($this->data['npm_lock']['packages'] ?? null);
    }

    /**
     * The database server, from Database::describe(). Null says it
     * couldn't be read.
     *
     * @param  array{engine: string, version: string|null, local: bool|null, managed: string|null}|null  $database
     */
    public function database(?array $database): self
    {
        $this->data['database'] = $database;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }

    public function toJson(): string
    {
        return (string) json_encode($this->data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public static function installedVersion(string $package): ?string
    {
        if (! class_exists(InstalledVersions::class) || ! InstalledVersions::isInstalled($package)) {
            return null;
        }

        return InstalledVersions::getPrettyVersion($package);
    }
}
