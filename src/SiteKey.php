<?php

namespace Porro\Core;

use InvalidArgumentException;

/**
 * A Porro site key: "porro_{site id}_{base64url seed}".
 *
 * The seed is the private half of an Ed25519 key pair. It never leaves the
 * site; Porro only stores the public half. Requests are signed over
 * "connector-v1\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{sha256 of body}",
 * so a signature only works for the endpoint it was made for.
 */
final class SiteKey
{
    private function __construct(
        public readonly string $siteId,
        private readonly string $seed,
    ) {}

    public static function parse(string $token): self
    {
        if (! preg_match('/^porro_([0-9a-z]{26})_([A-Za-z0-9_-]{43})$/', trim($token), $m)) {
            throw new InvalidArgumentException('That doesn’t look like a Porro site key. Copy it again from the site page in Porro.');
        }

        $seed = base64_decode(strtr($m[2], '-_', '+/'), true);

        if ($seed === false || strlen($seed) !== 32) {
            throw new InvalidArgumentException('That Porro site key is damaged. Create a new one from the site page in Porro.');
        }

        return new self(strtoupper($m[1]), $seed);
    }

    /**
     * @param  string  $path  the API path, e.g. "/api/v1/reports"
     * @return array{X-Porro-Site: string, X-Porro-Timestamp: string, X-Porro-Nonce: string, X-Porro-Signature: string}
     */
    public function headers(string $body, ?int $timestamp = null, string $method = 'POST', string $path = '/api/v1/reports'): array
    {
        $timestamp = (string) ($timestamp ?? time());
        $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
        $pair = sodium_crypto_sign_seed_keypair($this->seed);
        $message = self::message($method, $path, $timestamp, $nonce, $body);

        return [
            'X-Porro-Site' => $this->siteId,
            'X-Porro-Timestamp' => $timestamp,
            'X-Porro-Nonce' => $nonce,
            'X-Porro-Signature' => base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($pair))),
        ];
    }

    /**
     * A fingerprint of the key that's safe to log or use in cache keys:
     * the hash of the public half.
     */
    public function id(): string
    {
        return substr(hash('sha256', sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($this->seed))), 0, 16);
    }

    public static function message(string $method, string $path, string $timestamp, string $nonce, string $body): string
    {
        return "connector-v1\n".strtoupper($method)."\n".'/'.ltrim($path, '/')."\n".$timestamp."\n".$nonce."\n".hash('sha256', $body);
    }
}
