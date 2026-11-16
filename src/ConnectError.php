<?php

namespace Porro\Core;

use RuntimeException;

/**
 * Why connecting from the control panel didn't work, in words a person can
 * be shown. $reason says which case it is; $detail is what Porro said, when
 * it said anything. Neither ever holds the grant or the key.
 */
final class ConnectError extends RuntimeException
{
    /** Porro couldn't be reached, or answered with a server error. */
    public const UNREACHABLE = 'unreachable';

    /** The signature wasn't accepted. */
    public const SIGNATURE = 'signature';

    /** This server's clock is too far from Porro's. */
    public const CLOCK = 'clock';

    /** Someone turned the request down in the browser. */
    public const DENIED = 'denied';

    /** The grant isn't this request's, or whoever approved it has left the workspace. */
    public const GRANT = 'grant';

    /** Porro has no request with that id. */
    public const NOT_FOUND = 'not_found';

    /** Nobody has approved it yet. */
    public const NOT_APPROVED = 'not_approved';

    /** It ran out of time, or was already finished. */
    public const EXPIRED = 'expired';

    /** Porro didn't accept the site's details (its address or return URL, say). */
    public const INVALID = 'invalid';

    /** Too many attempts. */
    public const RATE_LIMITED = 'rate_limited';

    /** Porro answered with something this connector doesn't understand. */
    public const UNEXPECTED = 'unexpected';

    private const MESSAGES = [
        self::UNREACHABLE => 'Couldn’t reach Porro just now. Nothing has changed on this site. Try again in a minute.',
        self::SIGNATURE => 'Porro didn’t accept the request’s signature. Start again from the control panel.',
        self::CLOCK => 'This server’s clock is more than five minutes out, so Porro didn’t accept the request. Correct the server’s time, then try again.',
        self::DENIED => 'The request was turned down in Porro, so this site isn’t connected.',
        self::GRANT => 'Porro didn’t accept that approval for this site. Start again from the control panel.',
        self::NOT_FOUND => 'Porro has no record of this request. Start again from the control panel.',
        self::NOT_APPROVED => 'Nobody has approved this request in Porro yet. Start again from the control panel.',
        self::EXPIRED => 'This request ran out of time or was already used. Start again from the control panel.',
        self::INVALID => 'Porro didn’t accept this site’s details.',
        self::RATE_LIMITED => 'Too many attempts in a short time. Wait a minute, then try again.',
        self::UNEXPECTED => 'Porro’s answer wasn’t one this connector understands. Update the connector, then try again.',
    ];

    public function __construct(
        public readonly string $reason,
        public readonly int $status = 0,
        public readonly ?string $detail = null,
    ) {
        parent::__construct(self::MESSAGES[$reason] ?? self::MESSAGES[self::UNEXPECTED]);
    }

    /**
     * From Porro's answer to a connect call: its status, and its
     * {"ok": false, "error": "…"} body when there is one.
     *
     * @param  bool  $completing  the complete call, where 409 means "not approved yet" rather than a replay
     */
    public static function fromResponse(int $status, string $body, bool $completing = false): self
    {
        $json = json_decode($body, true);
        $said = is_array($json) && is_string($json['error'] ?? null) ? self::clean($json['error']) : null;

        $reason = match (true) {
            $status === 0 || $status >= 500 => self::UNREACHABLE,
            $status === 401 => $said !== null && stripos($said, 'clock') !== false ? self::CLOCK : self::SIGNATURE,
            // Porro answers 403 for all three; only its wording tells a
            // refusal apart from a grant that doesn't fit.
            $status === 403 => $said !== null && stripos($said, 'turned down') !== false ? self::DENIED : self::GRANT,
            $status === 404 => self::NOT_FOUND,
            // A replayed start is a fault on the way, not the person's doing.
            $status === 409 => $completing ? self::NOT_APPROVED : self::UNREACHABLE,
            $status === 410 => self::EXPIRED,
            $status === 413, $status === 422 => self::INVALID,
            $status === 429 => self::RATE_LIMITED,
            default => self::UNEXPECTED,
        };

        // A network error's text can name hosts and paths: not for the page.
        return new self($reason, $status, $status === 0 ? null : $said);
    }

    /**
     * Text from outside, made safe to show: one line, no markup, not long.
     */
    private static function clean(string $text): ?string
    {
        $text = trim((string) preg_replace('/\s+/', ' ', strip_tags($text)));

        if ($text === '') {
            return null;
        }

        // mbstring isn't required: the same fallback as Health\Advisories.
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, 300);
        }

        return preg_match('/^.{0,300}/su', $text, $m) ? $m[0] : substr($text, 0, 300);
    }
}
