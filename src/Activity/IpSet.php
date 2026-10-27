<?php

namespace Porro\Core\Activity;

/**
 * A fast "is this IP in the list" check for every request: exact
 * addresses in a hash set, ranges in a short list. Values are labels,
 * e.g. which list or reason an entry came from.
 */
final class IpSet
{
    /** @var array<string, string> */
    private array $exact = [];

    /** @var list<array{0: Cidr, 1: string}> */
    private array $ranges = [];

    /**
     * @param  iterable<string|Cidr, string>|iterable<int, string|Cidr>  $entries  cidr => label, or a list of cidrs
     */
    public static function of(iterable $entries): self
    {
        $set = new self;

        foreach ($entries as $key => $value) {
            [$cidr, $label] = is_int($key) ? [$value, ''] : [$key, $value];
            $set->add($cidr instanceof Cidr ? $cidr : Cidr::tryParse((string) $cidr), (string) $label);
        }

        return $set;
    }

    public function add(?Cidr $cidr, string $label = ''): void
    {
        if ($cidr === null) {
            return;
        }

        if ($cidr->isSingle()) {
            $this->exact[(string) $cidr] ??= $label;
        } else {
            $this->ranges[] = [$cidr, $label];
        }
    }

    /**
     * The label of the first entry covering $ip, or null.
     */
    public function match(string $ip): ?string
    {
        $cidr = Cidr::tryParse($ip);

        if ($cidr === null) {
            return null;
        }

        if (isset($this->exact[(string) $cidr])) {
            return $this->exact[(string) $cidr];
        }

        foreach ($this->ranges as [$range, $label]) {
            if ($range->contains($cidr)) {
                return $label;
            }
        }

        return null;
    }

    public function has(string $ip): bool
    {
        return $this->match($ip) !== null;
    }

    /**
     * The label of the first entry sharing any address with $cidr.
     */
    public function overlapping(Cidr $cidr): ?string
    {
        foreach ($this->exact as $ip => $label) {
            if ($cidr->contains($ip)) {
                return $label;
            }
        }

        foreach ($this->ranges as [$range, $label]) {
            if ($range->overlaps($cidr)) {
                return $label;
            }
        }

        return null;
    }

    public function count(): int
    {
        return count($this->exact) + count($this->ranges);
    }
}
