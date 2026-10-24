<?php

namespace Porro\Core\Health;

/**
 * One thing wrong with the site, found on the site itself or by Porro.
 * Kinds match Porro's finding kinds, so the two lists can be merged.
 */
final class Issue
{
    public const CRITICAL = 'critical';

    public const WARNING = 'warning';

    public const NOTICE = 'notice';

    public const SOURCE_SITE = 'site';

    public const SOURCE_PORRO = 'porro';

    public function __construct(
        public readonly string $kind,
        public readonly string $severity,
        public readonly string $title,
        public readonly ?string $detail = null,
        // A command that fixes it, shown as code. Advice goes in the detail.
        public readonly ?string $fix = null,
        public readonly ?string $url = null,
        public readonly string $source = self::SOURCE_SITE,
        // For Porro's findings: whether it's about the site or its server.
        public readonly string $scope = 'site',
        public readonly bool $acknowledged = false,
    ) {}

    /**
     * Porro's ranks, worst first: Down, Act now, Expiring, Unsupported,
     * Stale health, Updates.
     */
    public static function severityForRank(int $rank): string
    {
        return match (true) {
            $rank <= 2 => self::CRITICAL,
            $rank <= 4 => self::WARNING,
            default => self::NOTICE,
        };
    }

    public function weight(): int
    {
        return match ($this->severity) {
            self::CRITICAL => 0,
            self::WARNING => 1,
            default => 2,
        };
    }

    /**
     * @return array{kind: string, severity: string, title: string, detail: string|null, fix: string|null, url: string|null, source: string, scope: string, acknowledged: bool}
     */
    public function toArray(): array
    {
        return [
            'kind' => $this->kind,
            'severity' => $this->severity,
            'title' => $this->title,
            'detail' => $this->detail,
            'fix' => $this->fix,
            'url' => $this->url,
            'source' => $this->source,
            'scope' => $this->scope,
            'acknowledged' => $this->acknowledged,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['kind'] ?? ''),
            in_array($data['severity'] ?? null, [self::CRITICAL, self::WARNING, self::NOTICE], true) ? $data['severity'] : self::NOTICE,
            (string) ($data['title'] ?? ''),
            isset($data['detail']) ? (string) $data['detail'] : null,
            isset($data['fix']) ? (string) $data['fix'] : null,
            isset($data['url']) ? (string) $data['url'] : null,
            ($data['source'] ?? null) === self::SOURCE_PORRO ? self::SOURCE_PORRO : self::SOURCE_SITE,
            ($data['scope'] ?? null) === 'server' ? 'server' : 'site',
            (bool) ($data['acknowledged'] ?? false),
        );
    }

    /**
     * Worst first; the order they were found in otherwise.
     *
     * @param  list<self>  $issues
     * @return list<self>
     */
    public static function sort(array $issues): array
    {
        // usort is stable since PHP 8.0.
        usort($issues, fn (self $a, self $b) => [$a->weight(), $a->acknowledged] <=> [$b->weight(), $b->acknowledged]);

        return array_values($issues);
    }
}
