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
