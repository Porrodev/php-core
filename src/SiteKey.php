<?php

namespace Porro\Core;

use InvalidArgumentException;
use LogicException;
use SensitiveParameter;
use SensitiveParameterValue;

/**
 * A Porro site key: "porro_{site id}_{base64url seed}".
 *
 * The seed is the private half of an Ed25519 key pair. It never leaves the
 * site; Porro only stores the public half. Requests are signed over
 * "connector-v1\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{sha256 of body}",
 * so a signature only works for the endpoint it was made for.
 *
 * A key made on the site (generate()) has no site id until Porro gives it
 * one: it can sign the two connect calls, and becomes a full site key with
 * withSite().
 */
final class SiteKey
{
    /**
     * The seed, wrapped so it never shows in a dump, an export or a stack
     * trace, and can't be serialised.
     */
    private readonly SensitiveParameterValue $seed;

    private function __construct(
        public readonly ?string $siteId,
        #[SensitiveParameter]
        string $seed,
    ) {
        $this->seed = new SensitiveParameterValue($seed);
    }

    public static function parse(#[SensitiveParameter] string $token): self
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
     * A new key pair, made here. It has no site yet: use it to sign the
     * connect calls, then withSite() once Porro answers with the site's id.
     */
    public static function generate(): self
    {
        return new self(null, random_bytes(32));
    }

    /**
     * A key waiting for its site, from the seed() kept while the person
     * approves it in the browser.
     */
    public static function fromSeed(#[SensitiveParameter] string $seed): self
    {
        $bytes = preg_match('/^[A-Za-z0-9_-]{43}$/', $seed) ? base64_decode(strtr($seed, '-_', '+/'), true) : false;

        if ($bytes === false || strlen($bytes) !== 32) {
            throw new InvalidArgumentException('That isn’t a Porro key seed.');
        }

        return new self(null, $bytes);
    }

    /**
     * The same key, as the site Porro says it belongs to.
     */
    public function withSite(string $siteId): self
    {
        if (! preg_match('/^[0-9a-zA-Z]{26}$/', $siteId)) {
            throw new InvalidArgumentException('That isn’t a Porro site id.');
        }

        return new self(strtoupper($siteId), $this->seed->getValue());
    }

    /**
     * The public half, as Porro stores it: base64. Safe to send and show.
     */
    public function publicKey(): string
    {
        return base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($this->seed->getValue())));
    }

    /**
     * The private half, base64url. Secret: only ever kept encrypted on the
     * site, never logged, shown or sent.
     */
    public function seed(): string
    {
        return rtrim(strtr(base64_encode($this->seed->getValue()), '+/', '-_'), '=');
    }

    /**
     * The site key as it's stored: "porro_{site id}_{seed}". Secret, like
     * the seed inside it.
     */
    public function token(): string
    {
        if ($this->siteId === null) {
            throw new LogicException('This key has no site yet.');
        }

        return 'porro_'.strtolower($this->siteId).'_'.$this->seed();
    }

    /**
     * X-Porro-Site is left out while the key has no site (the connect calls).
     *
     * @param  string  $path  the API path, e.g. "/api/v1/reports"
     * @return array{X-Porro-Site?: string, X-Porro-Timestamp: string, X-Porro-Nonce: string, X-Porro-Signature: string}
     */
    public function headers(string $body, ?int $timestamp = null, string $method = 'POST', string $path = '/api/v1/reports'): array
    {
        $timestamp = (string) ($timestamp ?? time());
        $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');

        return ($this->siteId === null ? [] : ['X-Porro-Site' => $this->siteId]) + [
            'X-Porro-Timestamp' => $timestamp,
            'X-Porro-Nonce' => $nonce,
            'X-Porro-Signature' => $this->sign(self::message($method, $path, $timestamp, $nonce, $body)),
        ];
    }

    /**
     * The base64 Ed25519 signature of a message().
     */
    public function sign(string $message): string
    {
        $pair = sodium_crypto_sign_seed_keypair($this->seed->getValue());

        return base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($pair)));
    }

    /**
     * A fingerprint of the key that's safe to log or use in cache keys:
     * the hash of the public half.
     */
    public function id(): string
    {
        return substr(hash('sha256', sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($this->seed->getValue()))), 0, 16);
    }

    public static function message(string $method, string $path, string $timestamp, string $nonce, string $body): string
    {
        return "connector-v1\n".strtoupper($method)."\n".'/'.ltrim($path, '/')."\n".$timestamp."\n".$nonce."\n".hash('sha256', $body);
    }

    /**
     * A key is never serialised: not into a queued job, a cache or a
     * session. Keep its token(), encrypted, and parse() it again.
     *
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A Porro site key can’t be serialised. Store its token, encrypted, instead.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A Porro site key can’t be unserialised.');
    }

    /**
     * Never the seed, however the key is dumped.
     *
     * @return array{siteId: string|null, key: string}
     */
    public function __debugInfo(): array
    {
        return ['siteId' => $this->siteId, 'key' => $this->id()];
    }
}
