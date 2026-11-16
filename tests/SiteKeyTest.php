<?php

use Porro\Core\SiteKey;

it('parses a site key and signs requests Porro can verify', function () {
    $key = siteKey();
    $parsed = SiteKey::parse($key['token']);
    $headers = $parsed->headers('{"schema":1}');

    expect($parsed->siteId)->toBe($key['site'])
        ->and($headers['X-Porro-Site'])->toBe($key['site'])
        ->and(signatureIsValid($headers, '{"schema":1}', $key['public']))->toBeTrue()
        ->and(signatureIsValid($headers, '{"schema":2}', $key['public']))->toBeFalse();
});

it('binds the signature to the method and path', function () {
    $key = siteKey();
    $headers = SiteKey::parse($key['token'])->headers('', null, 'GET', '/api/v1/findings');

    expect(signatureIsValid($headers, '', $key['public'], 'GET', '/api/v1/findings'))->toBeTrue()
        ->and(signatureIsValid($headers, '', $key['public'], 'POST', '/api/v1/reports'))->toBeFalse()
        ->and(signatureIsValid($headers, '', $key['public'], 'GET', '/api/v1/reports'))->toBeFalse();
});

it('uses a fresh nonce for every request', function () {
    $parsed = SiteKey::parse(siteKey()['token']);

    expect($parsed->headers('a')['X-Porro-Nonce'])->not->toBe($parsed->headers('a')['X-Porro-Nonce']);
});

it('rejects things that are not site keys', function (string $token) {
    SiteKey::parse($token);
})->with(['', 'porro_short_key', 'lk_site_7hq2', 'porro_01jabcdefghjkmnpqrstvwxyz0_!!!!'])->throws(InvalidArgumentException::class);

it('makes a key on the site that signs before it has a site id', function () {
    $key = SiteKey::generate();
    $headers = $key->headers('{"a":1}', null, 'POST', '/api/v1/connect');
    $public = base64_decode($key->publicKey(), true);

    expect($key->siteId)->toBeNull()
        ->and(strlen($public))->toBe(32)
        ->and($headers)->not->toHaveKey('X-Porro-Site')
        ->and($headers['X-Porro-Nonce'])->toMatch('/^[A-Za-z0-9_-]{16,64}$/')
        ->and(signatureIsValid($headers, '{"a":1}', $public, 'POST', '/api/v1/connect'))->toBeTrue()
        ->and(SiteKey::generate()->publicKey())->not->toBe($key->publicKey());
});

it('becomes a site key once Porro gives it a site id', function () {
    $key = SiteKey::generate();
    $site = $key->withSite('01jabcdefghjkmnpqrstvwxyz0');
    $parsed = SiteKey::parse($site->token());

    expect($site->siteId)->toBe('01JABCDEFGHJKMNPQRSTVWXYZ0')
        ->and($site->token())->toMatch('/^porro_01jabcdefghjkmnpqrstvwxyz0_[A-Za-z0-9_-]{43}$/')
        ->and($parsed->publicKey())->toBe($key->publicKey())
        ->and($parsed->headers('')['X-Porro-Site'])->toBe('01JABCDEFGHJKMNPQRSTVWXYZ0')
        ->and(SiteKey::fromSeed($key->seed())->publicKey())->toBe($key->publicKey());
});

it('has no token until it has a site, and refuses bad site ids and seeds', function () {
    expect(fn () => SiteKey::generate()->token())->toThrow(LogicException::class)
        ->and(fn () => SiteKey::generate()->withSite('not-a-site'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => SiteKey::fromSeed('short'))->toThrow(InvalidArgumentException::class);
});

it('signs the connector-v1 message exactly as Porro verifies it', function () {
    // A fixed key, time and nonce, so any change to the message or the
    // signature shows up here before it shows up as a 401.
    $key = SiteKey::fromSeed(rtrim(strtr(base64_encode(str_repeat("\x07", 32)), '+/', '-_'), '='));
    $body = '{"address":"https://harbour-arts.org"}';
    $message = SiteKey::message('post', 'api/v1/connect', '1794700800', 'demo-nonce-0123456789', $body);

    expect($message)->toBe("connector-v1\nPOST\n/api/v1/connect\n1794700800\ndemo-nonce-0123456789\n72c9466baf955946071059806286e33d2189d5f448303fd6f4f703e33fa500af")
        ->and($key->publicKey())->toBe('6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=')
        ->and($key->sign($message))->toBe('7mhmzTXfmdB43mViaxiJ6UJMH0uqCEG5zrOk78gdwVwtMzayv6SlnqmpG1nIxS7sWqD59a9hIuVzcdHcsPUPCw==');
});

it('never gives the seed away when dumped', function () {
    $key = SiteKey::generate()->withSite('01jabcdefghjkmnpqrstvwxyz0');
    $dump = print_r($key, true).var_export($key->__debugInfo(), true);

    expect($dump)->not->toContain($key->seed())
        ->and($dump)->toContain($key->id());
});

it('keeps the seed out of var_export, casts and JSON', function () {
    $key = SiteKey::generate()->withSite('01jabcdefghjkmnpqrstvwxyz0');
    $raw = base64_decode(strtr($key->seed(), '-_', '+/'));
    $out = var_export($key, true).print_r((array) $key, true).json_encode($key).json_encode((array) $key, JSON_PARTIAL_OUTPUT_ON_ERROR);

    expect($out)->not->toContain($key->seed())
        ->and($out)->not->toContain($raw)
        ->and($out)->not->toContain(base64_encode($raw))
        // Still a working key.
        ->and(SiteKey::parse($key->token())->publicKey())->toBe($key->publicKey());
});

it('refuses to be serialised or unserialised', function () {
    $key = SiteKey::generate()->withSite('01jabcdefghjkmnpqrstvwxyz0');

    expect(fn () => serialize($key))->toThrow(LogicException::class)
        ->and(fn () => serialize(['key' => $key]))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:18:"Porro\\Core\\SiteKey":0:{}'))->toThrow(LogicException::class);
});
