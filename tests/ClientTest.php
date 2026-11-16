<?php

use Porro\Core\Client;
use Porro\Core\Report;
use Porro\Core\SiteKey;

function fakeTransport(array $responses, array &$calls): Closure
{
    return function (string $url, array $headers, string $body) use (&$responses, &$calls) {
        $calls[] = compact('url', 'headers', 'body');

        return array_shift($responses);
    };
}

it('sends a signed report to the reports endpoint', function () {
    $key = siteKey();
    $calls = [];
    $client = new Client(SiteKey::parse($key['token']), 'https://porro.test/', fakeTransport([[202, '{"ok":true,"need_lock":true}']], $calls), retries: 0);

    $result = $client->send(new Report('porro/laravel-connector', 'laravel'));

    expect($result->ok)->toBeTrue()
        ->and($result->needLock)->toBeTrue()
        ->and($calls[0]['url'])->toBe('https://porro.test/api/v1/reports')
        ->and(signatureIsValid($calls[0]['headers'], $calls[0]['body'], $key['public']))->toBeTrue()
        ->and(json_decode($calls[0]['body'], true))->toMatchArray(['schema' => 1, 'platform' => ['name' => 'laravel', 'version' => null, 'environment' => null]]);
});

it('passes on when Porro wants the npm packages', function () {
    $key = siteKey();
    $calls = [];
    $client = new Client(SiteKey::parse($key['token']), 'https://porro.test/', fakeTransport([[202, '{"ok":true,"need_lock":false,"need_npm_lock":true}']], $calls), retries: 0);

    $result = $client->send(new Report('porro/laravel-connector', 'laravel'));

    expect($result->needLock)->toBeFalse()
        ->and($result->needNpmLock)->toBeTrue();
});

it('retries network and server errors with a fresh signature, never rejections', function () {
    $calls = [];
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', fakeTransport([[0, 'timeout'], [503, ''], [202, '{"ok":true}']], $calls));

    expect($client->send(new Report('porro/laravel-connector', 'laravel'))->ok)->toBeTrue()
        ->and($calls)->toHaveCount(3)
        ->and($calls[0]['headers']['X-Porro-Nonce'])->not->toBe($calls[2]['headers']['X-Porro-Nonce']);

    $calls = [];
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', fakeTransport([[401, '{"ok":false,"error":"Invalid signature."}']], $calls));
    $result = $client->send(new Report('porro/laravel-connector', 'laravel'));

    expect($result->ok)->toBeFalse()
        ->and($result->error)->toBe('Invalid signature.')
        ->and($calls)->toHaveCount(1);
});

it('refuses a key that hasn’t finished connecting', function () {
    $calls = [];

    expect(fn () => new Client(SiteKey::generate(), 'https://porro.test', fakeTransport([[202, '{"ok":true}']], $calls)))
        ->toThrow(InvalidArgumentException::class, 'no site yet')
        ->and($calls)->toBeEmpty();
});

it('tells Porro the site has been disconnected, signed for that address only', function () {
    $key = siteKey();
    $calls = [];
    $client = new Client(SiteKey::parse($key['token']), 'https://porro.test/', fakeTransport([[200, '{"ok":true}']], $calls), retries: 0);

    $result = $client->disconnect();

    expect($result->ok)->toBeTrue()
        ->and($calls[0]['url'])->toBe('https://porro.test/api/v1/disconnect')
        ->and($calls[0]['body'])->toBe('{}')
        ->and(signatureIsValid($calls[0]['headers'], $calls[0]['body'], $key['public'], 'POST', '/api/v1/disconnect'))->toBeTrue()
        ->and(signatureIsValid($calls[0]['headers'], $calls[0]['body'], $key['public']))->toBeFalse();
});

it('says when Porro didn’t answer a disconnect', function () {
    $calls = [];
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', fakeTransport([[0, 'timeout']], $calls), retries: 0);

    $result = $client->disconnect();

    expect($result->ok)->toBeFalse()
        ->and($result->status)->toBe(0)
        ->and($result->keyTurnedAway())->toBeFalse();
});

it('knows a key Porro has turned away from a clock that is out', function () {
    $calls = [];
    $turnedAway = (new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', fakeTransport([[401, '{"ok":false,"error":"Invalid signature."}']], $calls)))
        ->send(new Report('porro/laravel-connector', 'laravel'));
    $clock = (new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', fakeTransport([[401, '{"ok":false,"error":"Report timestamp outside the allowed window. Check the server clock."}']], $calls)))
        ->send(new Report('porro/laravel-connector', 'laravel'));

    expect($turnedAway->keyTurnedAway())->toBeTrue()
        ->and($clock->keyTurnedAway())->toBeFalse();
});
