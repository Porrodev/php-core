<?php

namespace Porro\Core\Activity;

/**
 * One blocklist or safelist entry.
 */
final class Entry
{
    public const MANUAL = 'manual';

    public const SUGGESTED = 'suggested';

    public const CONFIG = 'config';

    public function __construct(
        // Normalised by Cidr: "203.0.113.0/24" or "203.0.113.7".
        public readonly string $cidr,
        // The reason for a block, the label for a safelist entry.
        public readonly string $note,
        public readonly string $source = self::MANUAL,
        public readonly int $addedAt = 0,
        public readonly ?int $expiresAt = null,
        public readonly ?string $addedBy = null,
    ) {}

    public function range(): Cidr
    {
        return Cidr::parse($this->cidr);
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= $now;
    }

    /**
     * @return array{cidr: string, note: string, source: string, added_at: int, expires_at: int|null, added_by: string|null}
     */
    public function toArray(): array
    {
        return [
            'cidr' => $this->cidr,
            'note' => $this->note,
            'source' => $this->source,
            'added_at' => $this->addedAt,
            'expires_at' => $this->expiresAt,
            'added_by' => $this->addedBy,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['cidr'] ?? ''),
            (string) ($data['note'] ?? ''),
            in_array($data['source'] ?? null, [self::MANUAL, self::SUGGESTED, self::CONFIG], true) ? $data['source'] : self::MANUAL,
            (int) ($data['added_at'] ?? 0),
            isset($data['expires_at']) ? (int) $data['expires_at'] : null,
            isset($data['added_by']) ? (string) $data['added_by'] : null,
        );
    }
}
