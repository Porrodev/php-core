<?php

use Porro\Core\ConnectClient;
use Porro\Core\ConnectError;
use Porro\Core\SiteKey;

const CONNECT_ID = '0196f3a2-7c41-7e0b-9d55-2f6a8c1e4b70';

function connectTransport(array $responses, array &$calls): Closure
{
    return function (string $url, array $headers, string $body) use (&$responses, &$calls) {
        $calls[] = compact('url', 'headers', 'body');

        return array_shift($responses);
    };
}

function startConnect(ConnectClient $client, SiteKey $key)
{
    return $client->start(
        $key,
        'https://harbour-arts.org',
        'https://harbour-arts.org/cp/porro/connect',
        ['name' => 'porro/statamic-connector', 'version' => '0.4.0'],
        ['name' => 'statamic', 'version' => '6.2.0', 'environment' => 'production'],
        '8.4.1',
    );
}

it('asks to connect, signed with the new key and no site header', function () {
    $key = SiteKey::generate();
    $calls = [];
    $client = new ConnectClient('https://porro.test/', connectTransport([
        [201, json_encode(['ok' => true, 'id' => CONNECT_ID, 'approve_url' => 'https://porro.test/connect/'.CONNECT_ID, 'expires_at' => '2026-11-15T10:10:00+00:00'])],
    ], $calls));

    $request = startConnect($client, $key);

    expect($request->id)->toBe(CONNECT_ID)
        ->and($request->approveUrl)->toBe('https://porro.test/connect/'.CONNECT_ID)
        ->and($request->expiresAt)->toBe('2026-11-15T10:10:00+00:00')
        ->and($calls)->toHaveCount(1)
        ->and($calls[0]['url'])->toBe('https://porro.test/api/v1/connect')
        ->and($calls[0]['headers'])->not->toHaveKey('X-Porro-Site')
        ->and(signatureIsValid($calls[0]['headers'], $calls[0]['body'], base64_decode($key->publicKey()), 'POST', '/api/v1/connect'))->toBeTrue()
        ->and(json_decode($calls[0]['body'], true))->toBe([
            'address' => 'https://harbour-arts.org',
            'return_url' => 'https://harbour-arts.org/cp/porro/connect',
            'public_key' => $key->publicKey(),
            'connector' => ['name' => 'porro/statamic-connector', 'version' => '0.4.0'],
            'platform' => ['name' => 'statamic', 'version' => '6.2.0', 'environment' => 'production'],
            'php' => ['version' => '8.4.1'],
        ])
        ->and($calls[0]['body'])->not->toContain($key->seed());
});

it('tries once more when Porro can’t be reached, then says so', function () {
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport([[0, 'Connection timed out to 10.0.0.4'], [503, '']], $calls));

    try {
        startConnect($client, SiteKey::generate());
        $this->fail('No error');
    } catch (ConnectError $e) {
        expect($e->reason)->toBe(ConnectError::UNREACHABLE)
            ->and($e->getMessage())->toContain('Couldn’t reach Porro')
            ->and($calls)->toHaveCount(2)
            ->and($calls[0]['headers']['X-Porro-Nonce'])->not->toBe($calls[1]['headers']['X-Porro-Nonce']);
    }

    // The network's own words never reach the page.
    $client = new ConnectClient('https://porro.test', connectTransport([[0, 'Connection timed out to 10.0.0.4'], [0, 'Connection timed out to 10.0.0.4']], $calls));

    expect(fn () => startConnect($client, SiteKey::generate()))->toThrow(function (ConnectError $e) {
        expect($e->detail)->toBeNull();
    });
});

it('only sends the browser to the Porro it’s set up for', function (string $approve) {
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport([[201, json_encode(['ok' => true, 'id' => CONNECT_ID, 'approve_url' => $approve])]], $calls));

    expect(fn () => startConnect($client, SiteKey::generate()))->toThrow(function (ConnectError $e) {
        expect($e->reason)->toBe(ConnectError::UNEXPECTED);
    });
})->with([
    'https://porro.test.kestrel-legal.com/connect/'.CONNECT_ID,
    'https://someone@porro.test/connect/'.CONNECT_ID,
    'http://porro.test/connect/'.CONNECT_ID,
    'https://porro.test:8443/connect/'.CONNECT_ID,
    'javascript:alert(1)',
    '/connect/'.CONNECT_ID,
]);

it('checks where a URL points before the browser follows it', function () {
    $client = new ConnectClient('https://porro.test/');

    expect($client->onPorro('https://porro.test/connect/'.CONNECT_ID))->toBeTrue()
        ->and($client->onPorro('https://PORRO.test/connect/'.CONNECT_ID.'?a=b'))->toBeTrue()
        ->and($client->onPorro('https://kestrel-legal.com/connect/'.CONNECT_ID))->toBeFalse()
        ->and($client->onPorro('//porro.test/connect'))->toBeFalse()
        ->and($client->onPorro(''))->toBeFalse()
        ->and((new ConnectClient('http://localhost:8010'))->onPorro('http://localhost:8010/connect/x'))->toBeTrue()
        ->and((new ConnectClient('http://localhost:8010'))->onPorro('http://localhost:9000/connect/x'))->toBeFalse();
});

it('finishes with the grant and returns the site key', function () {
    $key = SiteKey::generate();
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport([
        [200, json_encode(['ok' => true, 'site' => '01jabcdefghjkmnpqrstvwxyz0', 'host' => 'harbour-arts.org', 'workspace' => 'Marlowe Studio'])],
    ], $calls));

    $result = $client->complete($key, strtoupper(CONNECT_ID), 'grant-from-the-return-url');

    expect($result->key->siteId)->toBe('01JABCDEFGHJKMNPQRSTVWXYZ0')
        ->and($result->key->publicKey())->toBe($key->publicKey())
        ->and($result->key->token())->toStartWith('porro_01jabcdefghjkmnpqrstvwxyz0_')
        ->and($result->host)->toBe('harbour-arts.org')
        ->and($result->workspace)->toBe('Marlowe Studio')
        ->and($calls[0]['url'])->toBe('https://porro.test/api/v1/connect/'.CONNECT_ID.'/complete')
        ->and($calls[0]['headers'])->not->toHaveKey('X-Porro-Site')
        ->and(json_decode($calls[0]['body'], true))->toBe(['grant' => 'grant-from-the-return-url'])
        ->and(signatureIsValid($calls[0]['headers'], $calls[0]['body'], base64_decode($key->publicKey()), 'POST', '/api/v1/connect/'.CONNECT_ID.'/complete'))->toBeTrue();
});

it('never retries finishing, and never calls Porro with a bad id or grant', function () {
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport([[0, 'timeout'], [200, '{}']], $calls));

    expect(fn () => $client->complete(SiteKey::generate(), CONNECT_ID, 'grant'))->toThrow(ConnectError::class)
        ->and($calls)->toHaveCount(1);

    $calls = [];

    expect(fn () => $client->complete(SiteKey::generate(), '../reports', 'grant'))->toThrow(function (ConnectError $e) {
        expect($e->reason)->toBe(ConnectError::NOT_FOUND);
    })
        ->and(fn () => $client->complete(SiteKey::generate(), CONNECT_ID, ''))->toThrow(function (ConnectError $e) {
            expect($e->reason)->toBe(ConnectError::GRANT);
        })
        ->and($calls)->toBeEmpty();
});

it('turns each of Porro’s refusals into something a person can read', function (int $status, string $error, bool $completing, string $reason) {
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport(array_fill(0, 2, [$status, json_encode(['ok' => false, 'error' => $error])]), $calls));
    $key = SiteKey::generate();

    try {
        $completing ? $client->complete($key, CONNECT_ID, 'the-secret-grant') : startConnect($client, $key);
        $this->fail('No error');
    } catch (ConnectError $e) {
        expect($e->reason)->toBe($reason)
            ->and($e->status)->toBe($status)
            ->and($e->getMessage())->not->toBe('')
            ->and($e->getMessage().$e->detail)->not->toContain('the-secret-grant')
            ->and($e->getMessage().$e->detail)->not->toContain($key->seed());
    }
})->with([
    'bad signature' => [401, 'Invalid signature.', false, ConnectError::SIGNATURE],
    'clock' => [401, 'Request timestamp outside the allowed window. Check the server clock.', false, ConnectError::CLOCK],
    'replayed start' => [409, 'Request already received.', false, ConnectError::UNREACHABLE],
    'too large' => [413, 'Request too large.', false, ConnectError::INVALID],
    'invalid' => [422, 'The return URL must be on the site’s own address, over https.', false, ConnectError::INVALID],
    'rate limited' => [429, 'Too Many Attempts.', false, ConnectError::RATE_LIMITED],
    'turned down' => [403, 'The request was turned down in the browser.', true, ConnectError::DENIED],
    'grant mismatch' => [403, 'That grant doesn’t match this request.', true, ConnectError::GRANT],
    'approver left' => [403, 'Whoever approved this is no longer in that workspace. Start again from the control panel.', true, ConnectError::GRANT],
    'no such request' => [404, 'There’s no request with that id. Start again from the control panel.', true, ConnectError::NOT_FOUND],
    'not approved yet' => [409, 'Nobody has approved it yet.', true, ConnectError::NOT_APPROVED],
    'expired' => [410, 'This request has expired or was already used. Start again from the control panel.', true, ConnectError::EXPIRED],
    'server error' => [500, 'Server Error', true, ConnectError::UNREACHABLE],
]);

it('keeps what Porro said, cleaned up, and nothing else', function () {
    $error = ConnectError::fromResponse(422, json_encode(['error' => "<b>The address</b>\n must be the site’s URL."]));

    expect($error->detail)->toBe('The address must be the site’s URL.')
        ->and(ConnectError::fromResponse(502, '<html>Bad gateway</html>')->detail)->toBeNull();
});

it('won’t take an answer without a real site id', function (string $body) {
    $calls = [];
    $client = new ConnectClient('https://porro.test', connectTransport([[200, $body]], $calls));

    expect(fn () => $client->complete(SiteKey::generate(), CONNECT_ID, 'grant'))->toThrow(function (ConnectError $e) {
        expect($e->reason)->toBe(ConnectError::UNEXPECTED);
    });
})->with(['{"ok":true,"site":""}', '{"ok":true}', '{"ok":false,"site":"01jabcdefghjkmnpqrstvwxyz0"}', 'not json', '{"ok":true,"site":"../etc"}']);

it('never lets a throwing transport carry the grant or the key out in a trace', function () {
    $key = SiteKey::generate();
    $calls = 0;
    $client = new ConnectClient('https://porro.test', function (string $url, array $headers, string $body) use (&$calls) {
        $calls++;

        throw new RuntimeException('cURL error 28 while sending '.$body);
    });

    foreach ([fn () => $client->complete($key, CONNECT_ID, 'the-secret-grant'), fn () => startConnect($client, $key)] as $call) {
        try {
            $call();
            $this->fail('No error');
        } catch (ConnectError $e) {
            $everything = $e->getMessage().$e->detail.$e->getTraceAsString().json_encode($e->getTrace(), JSON_PARTIAL_OUTPUT_ON_ERROR).print_r($e->getTrace(), true);

            expect($e->reason)->toBe(ConnectError::UNREACHABLE)
                ->and($e->getPrevious())->toBeNull()
                ->and($everything)->not->toContain('the-secret-grant')
                ->and($everything)->not->toContain($key->seed())
                ->and($everything)->not->toContain('cURL error');
        }
    }

    // Finishing is tried once; asking, twice.
    expect($calls)->toBe(3);
});

it('cuts what Porro said to whole characters, and doesn’t need mbstring to', function () {
    $error = ConnectError::fromResponse(422, json_encode(['error' => str_repeat('é', 400)]));

    expect($error->detail)->toBe(str_repeat('é', 300))
        // The package doesn't require mbstring, so the call is guarded.
        ->and(file_get_contents(__DIR__.'/../src/ConnectError.php'))->toContain("function_exists('mb_substr')")
        ->and((string) json_encode(json_decode(file_get_contents(__DIR__.'/../composer.json'), true)['require']))->not->toContain('ext-mbstring');
});
