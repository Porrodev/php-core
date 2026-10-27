<?php

namespace Porro\Core\Activity;

/**
 * The site's blocklist and safelist, and the rules that keep a block
 * from taking the site down: never a protected range, never the admin's
 * own address, never anything safelisted, never too wide.
 *
 * Precedence: protected ranges, then the safelist, then the blocklist.
 * The rules live here, not in any control panel, so every connector and
 * every path (UI, command, sync) gets the same answers.
 */
final class Blocklist
{
    public const CAP = 5000;

    /** The widest block allowed: /16 for IPv4, /48 for IPv6. */
    public const WIDEST_V4 = 16;

    public const WIDEST_V6 = 48;

    /** How long a block suggested from activity lasts by default. */
    public const SUGGESTED_TTL = 7 * 86400;

    /**
     * @param  list<array{cidr: string, note?: string}|string>  $configSafe  safelist entries from config, which the panel can't remove
     */
    public function __construct(
        private readonly EntryStore $blocks,
        private readonly EntryStore $safe,
        private readonly ProtectedRanges $protected,
        private readonly array $configSafe = [],
    ) {}

    /**
     * @throws Refused
     */
    public function block(string $value, string $reason, string $source = Entry::MANUAL, ?int $expiresAt = null, ?string $by = null, ?string $actorIp = null, ?int $now = null): Entry
    {
        $now ??= time();
        $cidr = Cidr::tryParse($value) ?? throw new Refused(Refused::INVALID, "{$value} isn’t an IP address or range.");

        if ($cidr->prefix < ($cidr->isV4() ? self::WIDEST_V4 : self::WIDEST_V6)) {
            throw new Refused(Refused::TOO_WIDE, sprintf('%s is too wide to block: the widest allowed is /%d.', $cidr, $cidr->isV4() ? self::WIDEST_V4 : self::WIDEST_V6));
        }

        if (($protectedBy = $this->protected->overlapping($cidr)) !== null) {
            $label = $protectedBy === ProtectedRanges::RESERVED ? 'private or reserved' : ProtectedRanges::label($protectedBy);

            throw new Refused(Refused::PROTECTED, $cidr->isSingle()
                ? "{$cidr} is a {$label} address, which has to reach this site."
                : "{$cidr} covers {$label} addresses, which have to reach this site.");
        }

        if ($actorIp !== null && $cidr->contains($actorIp)) {
            throw new Refused(Refused::OWN_IP, $cidr->isSingle() ? 'That’s your own IP address.' : "{$cidr} covers your own IP address.");
        }

        if (($safe = $this->safeOverlapping($cidr, $now)) !== null) {
            throw new Refused(Refused::SAFELISTED, "{$cidr} is on the safelist ({$safe->note}). Remove it there first.");
        }

        $current = $this->active($this->blocks->all(), $now);

        if (count($current) >= self::CAP && ! $this->has($current, (string) $cidr)) {
            throw new Refused(Refused::FULL, 'The blocklist is full ('.self::CAP.' entries). Remove some, or block a range instead.');
        }

        $entry = new Entry((string) $cidr, trim($reason), $source, $now, $expiresAt, $by);
        $this->blocks->put($entry);

        return $entry;
    }

    public function unblock(string $value): void
    {
        $this->blocks->remove((string) (Cidr::tryParse($value) ?? $value));
    }

    /**
     * @throws Refused
     */
    public function safelist(string $value, string $label, ?int $expiresAt = null, ?string $by = null, bool $confirmWide = false, ?int $now = null): Entry
    {
        $cidr = Cidr::tryParse($value) ?? throw new Refused(Refused::INVALID, "{$value} isn’t an IP address or range.");

        if (trim($label) === '') {
            throw new Refused(Refused::NO_LABEL, 'Give it a label, e.g. “1994 office”, so others know why it’s here.');
        }

        if (! $confirmWide && $cidr->prefix < ($cidr->isV4() ? self::WIDEST_V4 : self::WIDEST_V6)) {
            throw new Refused(Refused::NEEDS_CONFIRM, sprintf('%s covers %s addresses. Confirm to safelist all of them.', $cidr, $cidr->size() === PHP_INT_MAX ? 'billions of' : number_format($cidr->size())));
        }

        $entry = new Entry((string) $cidr, trim($label), Entry::MANUAL, $now ?? time(), $expiresAt, $by);
        $this->safe->put($entry);

        return $entry;
    }

    /**
     * @throws Refused
     */
    public function unsafelist(string $value): void
    {
        $cidr = (string) (Cidr::tryParse($value) ?? $value);

        foreach ($this->configEntries() as $entry) {
            if ($entry->cidr === $cidr) {
                throw new Refused(Refused::FROM_CONFIG, "{$cidr} comes from the site’s config, so it can only be removed there.");
            }
        }

        $this->safe->remove($cidr);
    }

    /**
     * @return list<Entry>
     */
    public function blocks(?int $now = null): array
    {
        return $this->active($this->blocks->all(), $now ?? time());
    }

    /**
     * Safelist entries, config ones first.
     *
     * @return list<Entry>
     */
    public function safe(?int $now = null): array
    {
        return [...$this->configEntries(), ...$this->active($this->safe->all(), $now ?? time())];
    }

    public function isSafelisted(string $ip, ?int $now = null): bool
    {
        $cidr = Cidr::tryParse($ip);

        return $cidr !== null && $this->safeOverlapping($cidr, $now ?? time()) !== null;
    }

    /**
     * Removes what no longer belongs: expired entries, and blocks that now
     * overlap the safelist or a protected range (e.g. a new Forge IP).
     * Returns what went, and why, for the panel and the log.
     *
     * @return list<array{list: string, cidr: string, why: string}>
     */
    public function prune(?int $now = null): array
    {
        $now ??= time();
        $removed = [];

        foreach ($this->safe->all() as $entry) {
            if ($entry->isExpired($now)) {
                $this->safe->remove($entry->cidr);
                $removed[] = ['list' => 'safelist', 'cidr' => $entry->cidr, 'why' => 'expired'];
            }
        }

        foreach ($this->blocks->all() as $entry) {
            $cidr = Cidr::tryParse($entry->cidr);
            $why = match (true) {
                $cidr === null => 'not an IP address',
                $entry->isExpired($now) => 'expired',
                ($source = $this->protected->overlapping($cidr)) !== null => 'now a '.($source === ProtectedRanges::RESERVED ? 'private or reserved' : ProtectedRanges::label($source)).' address',
                ($safe = $this->safeOverlapping($cidr, $now)) !== null => "now safelisted ({$safe->note})",
                default => null,
            };

            if ($why !== null) {
                $this->blocks->remove($entry->cidr);
                $removed[] = ['list' => 'blocklist', 'cidr' => $entry->cidr, 'why' => $why];
            }
        }

        return $removed;
    }

    /**
     * Every active block, ready to check each request against.
     */
    public function matcher(?int $now = null): IpSet
    {
        $set = new IpSet;

        foreach ($this->blocks($now) as $entry) {
            $set->add(Cidr::tryParse($entry->cidr), $entry->note);
        }

        return $set;
    }

    private function safeOverlapping(Cidr $cidr, int $now): ?Entry
    {
        foreach ($this->safe($now) as $entry) {
            $range = Cidr::tryParse($entry->cidr);

            if ($range !== null && $range->overlaps($cidr)) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * @return list<Entry>
     */
    private function configEntries(): array
    {
        $entries = [];

        foreach ($this->configSafe as $item) {
            $value = is_array($item) ? ($item['cidr'] ?? '') : $item;
            $cidr = Cidr::tryParse((string) $value);

            if ($cidr !== null) {
                $entries[] = new Entry((string) $cidr, is_array($item) ? (string) ($item['note'] ?? '') : '', Entry::CONFIG);
            }
        }

        return $entries;
    }

    /**
     * @param  list<Entry>  $entries
     * @return list<Entry>
     */
    private function active(array $entries, int $now): array
    {
        return array_values(array_filter($entries, fn (Entry $entry) => ! $entry->isExpired($now)));
    }

    /**
     * @param  list<Entry>  $entries
     */
    private function has(array $entries, string $cidr): bool
    {
        foreach ($entries as $entry) {
            if ($entry->cidr === $cidr) {
                return true;
            }
        }

        return false;
    }
}
