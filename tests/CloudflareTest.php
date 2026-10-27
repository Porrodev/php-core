<?php

use Porro\Core\Activity\Cloudflare;
use Porro\Core\Activity\CloudflareError;
use Porro\Core\Activity\Entry;

/**
 * Just enough of Cloudflare's API, in memory: zones, lists and their
 * items (paged two at a time), zone rulesets and bulk operations.
 */
final class FakeCloudflare
{
    /** @var list<array{0: string, 1: string, 2: mixed}> */
    public array $calls = [];

    /** @var array<string, array<string, mixed>> */
    public array $zones = ['example.co.uk' => ['id' => 'z1', 'name' => 'example.co.uk', 'account' => ['id' => 'a1']]];

    /** @var array<string, array{id: string, name: string, kind: string}> */
    public array $lists = [];

    /** @var array<string, list<array{id: string, ip: string, comment: string}>> */
    public array $items = [];

    /** @var array<string, array<string, mixed>>|null zone id => entrypoint ruleset */
    public array $rulesets = [];

    public bool $tokenActive = true;

    public ?string $failListCreate = null;

    public ?string $failOperation = null;

    private int $ids = 0;

    public function http(): Closure
    {
        return function (string $method, string $url, array $headers, ?string $body) {
            $path = substr($url, strlen(Cloudflare::API));
            $data = $body === null ? null : json_decode($body, true);
            $this->calls[] = [$method, $path, $data];

            if (($headers['Authorization'] ?? '') !== 'Bearer token') {
                return $this->fail(401, 'Invalid API Token');
            }

            return $this->route($method, $path, $data);
        };
    }

    public function methods(): array
    {
        return array_map(fn ($c) => "{$c[0]} ".strtok($c[1], '?'), $this->calls);
    }

    private function route(string $method, string $path, mixed $data): array
    {
        $query = [];
        parse_str((string) parse_url($path, PHP_URL_QUERY), $query);
        $path = (string) parse_url($path, PHP_URL_PATH);

        return match (true) {
            $path === '/user/tokens/verify' => $this->ok(['status' => $this->tokenActive ? 'active' : 'disabled']),
            $path === '/zones' => $this->ok(isset($this->zones[$query['name'] ?? '']) ? [$this->zones[$query['name']]] : []),
            $method === 'GET' && $path === '/accounts/a1/rules/lists' => $this->ok(array_values($this->lists)),
            $method === 'POST' && $path === '/accounts/a1/rules/lists' => $this->createList($data),
            (bool) preg_match('#^/accounts/a1/rules/lists/bulk_operations/(\w+)$#', $path) => $this->failOperation
                ? $this->ok(['status' => 'failed', 'error' => $this->failOperation])
                : $this->ok(['status' => 'completed']),
            (bool) preg_match('#^/accounts/a1/rules/lists/(\w+)/items$#', $path, $m) => $this->listItems($method, $m[1], $data, $query),
            $method === 'DELETE' && (bool) preg_match('#^/accounts/a1/rules/lists/(\w+)$#', $path, $m) => $this->deleteList($m[1]),
            (bool) preg_match('#^/zones/(\w+)/rulesets/phases/http_request_firewall_custom/entrypoint$#', $path, $m) => isset($this->rulesets[$m[1]])
                ? $this->ok($this->rulesets[$m[1]])
                : $this->fail(404, 'Could not find entrypoint ruleset'),
            $method === 'POST' && (bool) preg_match('#^/zones/(\w+)/rulesets$#', $path, $m) => $this->createRuleset($m[1], $data),
            $method === 'POST' && (bool) preg_match('#^/zones/(\w+)/rulesets/(\w+)/rules$#', $path, $m) => $this->addRule($m[1], $data),
            $method === 'DELETE' && (bool) preg_match('#^/zones/(\w+)/rulesets/(\w+)/rules/(\w+)$#', $path, $m) => $this->deleteRule($m[1], $m[3]),
            default => $this->fail(404, "No route {$method} {$path}"),
        };
    }

    private function createList(array $data): array
    {
        if ($this->failListCreate) {
            return $this->fail(400, $this->failListCreate);
        }

        $id = 'l'.(++$this->ids);
        $this->lists[$id] = ['id' => $id, 'name' => $data['name'], 'kind' => $data['kind']];
        $this->items[$id] = [];

        return $this->ok($this->lists[$id]);
    }

    private function deleteList(string $id): array
    {
        unset($this->lists[$id], $this->items[$id]);

        return $this->ok(['id' => $id]);
    }

    private function listItems(string $method, string $list, mixed $data, array $query): array
    {
        if ($method === 'GET') {
            $offset = (int) ($query['cursor'] ?? 0);
            $page = array_slice($this->items[$list], $offset, 2);
            $next = $offset + 2 < count($this->items[$list]) ? (string) ($offset + 2) : null;

            return [200, json_encode(['success' => true, 'result' => $page, 'result_info' => ['cursors' => array_filter(['after' => $next])]])];
        }

        if ($method === 'POST') {
            foreach ($data as $item) {
                // Like Cloudflare: the same IP again replaces its comment.
                $this->items[$list] = array_values(array_filter($this->items[$list], fn ($i) => $i['ip'] !== $item['ip']));
                $this->items[$list][] = ['id' => 'i'.(++$this->ids), 'ip' => $item['ip'], 'comment' => $item['comment']];
            }
        }

        if ($method === 'DELETE') {
            $ids = array_column($data['items'], 'id');
            $this->items[$list] = array_values(array_filter($this->items[$list], fn ($i) => ! in_array($i['id'], $ids, true)));
        }

        if ($method === 'PUT') {
            return $this->fail(400, 'The fake refuses PUT: it would replace every site’s items');
        }

        return $this->ok(['operation_id' => 'op'.(++$this->ids)]);
    }

    private function createRuleset(string $zone, array $data): array
    {
        $this->rulesets[$zone] = ['id' => 'rs'.(++$this->ids), 'phase' => $data['phase'], 'rules' => array_map(fn ($r) => $r + ['id' => 'r'.(++$this->ids)], $data['rules'])];

        return $this->ok($this->rulesets[$zone]);
    }

    private function addRule(string $zone, array $rule): array
    {
        $this->rulesets[$zone]['rules'][] = $rule + ['id' => 'r'.(++$this->ids)];

        return $this->ok($this->rulesets[$zone]);
    }

    private function deleteRule(string $zone, string $rule): array
    {
        $this->rulesets[$zone]['rules'] = array_values(array_filter($this->rulesets[$zone]['rules'], fn ($r) => $r['id'] !== $rule));

        return $this->ok($this->rulesets[$zone]);
    }

    private function ok(mixed $result): array
    {
        return [200, json_encode(['success' => true, 'errors' => [], 'result' => $result])];
    }

    private function fail(int $status, string $message): array
    {
        return [$status, json_encode(['success' => false, 'errors' => [['code' => 10000 + $status, 'message' => $message]], 'result' => null])];
    }
}

function cloudflare(FakeCloudflare $fake, string $token = 'token'): Cloudflare
{
    return new Cloudflare($token, $fake->http(), fn () => null);
}

beforeEach(function () {
    $this->fake = new FakeCloudflare;
});

it('checks the token is active', function () {
    cloudflare($this->fake)->verify();

    $this->fake->tokenActive = false;
    expect(fn () => cloudflare($this->fake)->verify())->toThrow(CloudflareError::class, 'isn’t active');

    expect(fn () => cloudflare($this->fake, 'wrong')->verify())->toThrow(CloudflareError::class, 'refused the token: Invalid API Token');
});

it('finds the zone from a subdomain', function () {
    expect(cloudflare($this->fake)->zoneFor('www.shop.example.co.uk'))->toBe(['id' => 'z1', 'name' => 'example.co.uk', 'account' => 'a1'])
        ->and(fn () => cloudflare($this->fake)->zoneFor('elsewhere.test'))->toThrow(CloudflareError::class, 'No active Cloudflare zone');
});

it('creates the list and starts the zone’s custom rules when there are none', function () {
    $connection = cloudflare($this->fake)->connect('www.example.co.uk');

    expect($connection)->toMatchArray(['account' => 'a1', 'zone' => 'z1', 'zone_name' => 'example.co.uk'])
        ->and($this->fake->lists[$connection['list']]['name'])->toBe('porro_blocklist')
        ->and($this->fake->rulesets['z1']['rules'])->toHaveCount(1)
        ->and($this->fake->rulesets['z1']['rules'][0])->toMatchArray(['action' => 'block', 'expression' => 'ip.src in $porro_blocklist', 'id' => $connection['rule']]);
});

it('adds its rule next to the zone’s own rules, never replacing them', function () {
    $this->fake->rulesets['z1'] = ['id' => 'rsclient', 'rules' => [['id' => 'rclient', 'expression' => 'http.request.uri.path eq "/wp-admin"', 'action' => 'block']]];

    $connection = cloudflare($this->fake)->connect('example.co.uk');

    expect(array_column($this->fake->rulesets['z1']['rules'], 'id'))->toBe(['rclient', $connection['rule']])
        ->and($connection['ruleset'])->toBe('rsclient')
        ->and($this->fake->methods())->not->toContain('PUT /zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint');
});

it('reuses what’s there when connecting again', function () {
    $first = cloudflare($this->fake)->connect('example.co.uk');
    $this->fake->calls = [];

    $second = cloudflare($this->fake)->connect('example.co.uk');

    expect($second)->toBe($first)
        ->and(array_filter($this->fake->methods(), fn ($m) => ! str_starts_with($m, 'GET')))->toBe([]);
});

it('explains when the account’s list can’t be created', function () {
    $this->fake->failListCreate = 'Exceeded the maximum number of lists for this account';

    expect(fn () => cloudflare($this->fake)->connect('example.co.uk'))
        ->toThrow(CloudflareError::class, 'The Free plan allows one custom list per account');
});

it('syncs only this site’s items, leaving other sites’ alone', function () {
    $cf = cloudflare($this->fake);
    $connection = $cf->connect('example.co.uk');
    $list = $connection['list'];
    $this->fake->items[$list] = [
        ['id' => 'x1', 'ip' => '103.75.190.0/24', 'comment' => 'porro:other-site:Scanner'],
        ['id' => 'x2', 'ip' => '45.148.10.92', 'comment' => 'porro:dog-ear:Old block'],
        ['id' => 'x3', 'ip' => '198.18.0.1', 'comment' => 'Added by hand in Cloudflare'],
    ];

    $result = $cf->sync($connection, 'dog-ear', [
        new Entry('185.220.101.4', 'Probing for .env'),
        new Entry('103.75.190.0/24', 'Same network, blocked by the other site'),
        new Entry('2A03:B0C0:0003:00D0:0000:0000:01A2:F001', 'v6'),
    ]);

    expect($result)->toBe(['added' => 2, 'removed' => 1, 'shared' => 1])
        ->and(array_column($this->fake->items[$list], 'comment', 'ip'))->toBe([
            '103.75.190.0/24' => 'porro:other-site:Scanner',
            '198.18.0.1' => 'Added by hand in Cloudflare',
            '185.220.101.4' => 'porro:dog-ear:Probing for .env',
            '2a03:b0c0:3:d0::1a2:f001' => 'porro:dog-ear:v6',
        ])
        ->and($this->fake->methods())->not->toContain("PUT /accounts/a1/rules/lists/{$list}/items");
});

it('does nothing when the list already matches', function () {
    $cf = cloudflare($this->fake);
    $connection = $cf->connect('example.co.uk');
    $cf->sync($connection, 'dog-ear', [new Entry('185.220.101.4', 'x')]);
    $this->fake->calls = [];

    expect($cf->sync($connection, 'dog-ear', [new Entry('185.220.101.4', 'x')]))->toBe(['added' => 0, 'removed' => 0, 'shared' => 0])
        ->and(array_filter($this->fake->methods(), fn ($m) => ! str_starts_with($m, 'GET')))->toBe([]);
});

it('reads every page of the list', function () {
    $cf = cloudflare($this->fake);
    $connection = $cf->connect('example.co.uk');
    $entries = array_map(fn ($i) => new Entry("45.148.10.{$i}", 'x'), range(1, 7));
    $cf->sync($connection, 'dog-ear', $entries);

    // Seven items at two a page: a second sync must see them all and add nothing.
    expect($cf->sync($connection, 'dog-ear', $entries)['added'])->toBe(0);
});

it('reports a failed list update', function () {
    $cf = cloudflare($this->fake);
    $connection = $cf->connect('example.co.uk');
    $this->fake->failOperation = 'invalid IP';

    expect(fn () => $cf->sync($connection, 'dog-ear', [new Entry('185.220.101.4', 'x')]))->toThrow(CloudflareError::class, 'invalid IP');
});

it('disconnects: its items and rule go, the list only when empty', function () {
    $cf = cloudflare($this->fake);
    $connection = $cf->connect('example.co.uk');
    $cf->sync($connection, 'dog-ear', [new Entry('185.220.101.4', 'x')]);
    $this->fake->items[$connection['list']][] = ['id' => 'x1', 'ip' => '103.75.190.0/24', 'comment' => 'porro:other-site:x'];

    $cf->disconnect($connection, 'dog-ear');

    expect($this->fake->items[$connection['list']])->toHaveCount(1)
        ->and($this->fake->rulesets['z1']['rules'])->toBe([]);

    $cf->sync($connection, 'other-site', []);
    $cf->disconnect($connection, 'other-site');

    expect($this->fake->lists)->toBe([]);
});

it('keeps comments short and recognisable', function () {
    expect(Cloudflare::comment('dog-ear', "Flagged:\n probe ×41"))->toBe('porro:dog-ear:Flagged: probe ×41')
        ->and(strlen(Cloudflare::comment('dog-ear', str_repeat('x', 200))))->toBeLessThan(110);
});
