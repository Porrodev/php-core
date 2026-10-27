<?php

namespace Porro\Core\Activity;

use InvalidArgumentException;

/**
 * An IPv4 or IPv6 address or range. A bare address is a /32 or /128.
 * Always normalised: "203.0.113.7/24" becomes "203.0.113.0/24".
 */
final class Cidr
{
    private function __construct(
        // The network address, packed (4 or 16 bytes).
        private readonly string $network,
        public readonly int $prefix,
    ) {}

    public static function parse(string $value): self
    {
        $cidr = self::tryParse($value);

        if ($cidr === null) {
            throw new InvalidArgumentException("Not an IP address or range: {$value}");
        }

        return $cidr;
    }

    public static function tryParse(string $value): ?self
    {
        $value = trim($value);
        $prefix = null;

        if (str_contains($value, '/')) {
            [$value, $bits] = explode('/', $value, 2);

            if (! ctype_digit($bits)) {
                return null;
            }

            $prefix = (int) $bits;
        }

        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($value);
        $max = strlen($packed) * 8;
        $prefix ??= $max;

        if ($prefix > $max) {
            return null;
        }

        return new self(self::mask($packed, $prefix), $prefix);
    }

    public static function isValid(string $value): bool
    {
        return self::tryParse($value) !== null;
    }

    public function isV4(): bool
    {
        return strlen($this->network) === 4;
    }

    public function isSingle(): bool
    {
        return $this->prefix === strlen($this->network) * 8;
    }

    /**
     * How many addresses it covers, capped at PHP_INT_MAX for wide IPv6.
     */
    public function size(): int
    {
        $bits = strlen($this->network) * 8 - $this->prefix;

        return $bits >= 63 ? PHP_INT_MAX : 1 << $bits;
    }

    public function contains(string|self $ip): bool
    {
        $other = $ip instanceof self ? $ip : self::tryParse($ip);

        if ($other === null || strlen($other->network) !== strlen($this->network) || $other->prefix < $this->prefix) {
            return false;
        }

        return self::mask($other->network, $this->prefix) === $this->network;
    }

    /**
     * True when the two ranges share any address.
     */
    public function overlaps(self $other): bool
    {
        return $this->contains($other) || $other->contains($this);
    }

    public function __toString(): string
    {
        $address = inet_ntop($this->network);

        return $this->isSingle() ? $address : "{$address}/{$this->prefix}";
    }

    private static function mask(string $packed, int $prefix): string
    {
        $out = '';

        foreach (str_split($packed) as $i => $byte) {
            $keep = max(0, min(8, $prefix - $i * 8));
            $out .= chr(ord($byte) & (0xFF << (8 - $keep)) & 0xFF);
        }

        return $out;
    }
}
