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

it('uses a fresh nonce for every request', function () {
    $parsed = SiteKey::parse(siteKey()['token']);

    expect($parsed->headers('a')['X-Porro-Nonce'])->not->toBe($parsed->headers('a')['X-Porro-Nonce']);
});

it('rejects things that are not site keys', function (string $token) {
    SiteKey::parse($token);
})->with(['', 'porro_short_key', 'lk_site_7hq2', 'porro_01jabcdefghjkmnpqrstvwxyz0_!!!!'])->throws(InvalidArgumentException::class);
