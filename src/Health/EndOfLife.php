<?php

namespace Porro\Core\Health;

use DateTimeImmutable;

/**
 * PHP and platform versions past, or close to, the end of security
 * support. Dates come from endoflife.date, fetched once a day, with a
 * copy bundled in data/endoflife.json for when it can't be reached.
 */
final class EndOfLife
{
    public const WARN_DAYS = 90;

    private const TTL = 86400;

    /**
     * Product on endoflife.date, version parts in a cycle, and its name.
     */
    public const PRODUCTS = [
        'php' => ['php', 2, 'PHP'],
        'laravel' => ['laravel', 1, 'Laravel'],
        'craft' => ['craft-cms', 1, 'Craft'],
        'statamic' => ['statamic', 1, 'Statamic'],
    ];

    public function __construct(
        private readonly Sources $sources,
        private readonly ?DateTimeImmutable $today = null,
    ) {}

    /**
     * @param  string  $product  a key of PRODUCTS, e.g. "php" or "craft"
     */
    public function check(string $product, ?string $version): ?Issue
    {
        if (! isset(self::PRODUCTS[$product]) || ! ($cycle = self::cycle($version, self::PRODUCTS[$product][1]))) {
            return null;
        }

        [$slug, , $label] = self::PRODUCTS[$product];
        $cycles = $this->cycles($slug);
        $support = $cycles[$cycle] ?? null;
        $until = $support ? self::date($support['eol']) : null;

        if (! $until) {
            return null;
        }

        $today = ($this->today ?? new DateTimeImmutable('today'))->setTime(0, 0);
        $newest = $this->newest($cycles, $today);
        $upgrade = $newest && $newest !== $cycle ? "Upgrade to {$label} {$newest}" : null;
        $kind = $product === 'php' ? 'unsupported_php' : 'unsupported_platform';

        if ($until < $today) {
            return new Issue(
                $kind,
                Issue::WARNING,
                "{$label} {$cycle} is past security support",
                "{$label} {$version} · security support ended ".$until->format('j M Y').' · it no longer gets security fixes',
                $upgrade,
            );
        }

        $days = (int) $today->diff($until)->days;

        if ($days <= self::WARN_DAYS) {
            return new Issue(
                $kind === 'unsupported_php' ? 'php_ending_soon' : 'platform_ending_soon',
                Issue::NOTICE,
                "{$label} {$cycle} security support ends in {$days} ".($days === 1 ? 'day' : 'days'),
                "{$label} {$version} · ends ".$until->format('j M Y'),
                $upgrade,
            );
        }

        return null;
    }

    /**
     * "8.3.12" → "8.3"; with one part, "5.4.1" → "5".
     */
    public static function cycle(?string $version, int $parts = 2): ?string
    {
        if (! $version || ! preg_match('/^v?(\d+)(?:\.(\d+))?/', $version, $m)) {
            return null;
        }

        return $parts === 1 || ! isset($m[2]) ? $m[1] : "{$m[1]}.{$m[2]}";
    }

    /**
     * @return array<string, array{cycle: string, eol: mixed}>
     */
    private function cycles(string $slug): array
    {
        $fetched = $this->sources->remember("eol:{$slug}", self::TTL, function () use ($slug) {
            $data = $this->sources->json('GET', "https://endoflife.date/api/{$slug}.json");

            return is_array($data) && array_is_list($data) && $data !== [] ? $data : null;
        });

        $list = is_array($fetched) ? $fetched : (self::bundled()[$slug] ?? []);
        $cycles = [];

        foreach ($list as $cycle) {
            if (is_array($cycle) && isset($cycle['cycle'])) {
                $cycles[(string) $cycle['cycle']] = ['cycle' => (string) $cycle['cycle'], 'eol' => $cycle['eol'] ?? null];
            }
        }

        return $cycles;
    }

    /**
     * The newest cycle still supported.
     *
     * @param  array<string, array{cycle: string, eol: mixed}>  $cycles
     */
    private function newest(array $cycles, DateTimeImmutable $today): ?string
    {
        $supported = array_filter($cycles, function (array $cycle) use ($today) {
            $until = self::date($cycle['eol']);

            return $cycle['eol'] === false || ($until && $until >= $today);
        });

        $names = array_keys($supported);
        usort($names, fn ($a, $b) => version_compare((string) $b, (string) $a));

        return isset($names[0]) ? (string) $names[0] : null;
    }

    /**
     * "eol" is the end of security support: a date, or true/false when
     * there's no date (ended, or not yet).
     */
    private static function date(mixed $eol): ?DateTimeImmutable
    {
        if ($eol === true) {
            return new DateTimeImmutable('yesterday');
        }

        if (! is_string($eol) || ! preg_match('/^\d{4}-\d{2}-\d{2}$/', $eol)) {
            return null;
        }

        return new DateTimeImmutable($eol);
    }

    /**
     * @return array<string, list<array{cycle: string, eol: mixed}>>
     */
    private static function bundled(): array
    {
        static $products = null;

        return $products ??= (array) (json_decode((string) @file_get_contents(__DIR__.'/../../data/endoflife.json'), true)['products'] ?? []);
    }
}
