<?php

namespace Porro\Core\Activity;

use Closure;
use Throwable;

/**
 * Blocks at Cloudflare's edge: one account IP List, "porro_blocklist",
 * and one custom rule on the site's zone that blocks what's in it.
 *
 * The list belongs to the whole Cloudflare account, so every site on it
 * shares it. Each site only ever adds and removes items whose comment
 * starts "porro:{site id}:", and never replaces the list wholesale. An IP
 * another site already added is left as it is: it's blocked either way,
 * and the other site owns it. If that site removes it, the next sync here
 * adds it back.
 *
 * The rule is added next to the zone's existing custom rules, never by
 * replacing the phase's ruleset, which would delete the client's own.
 *
 * Token permissions: Account Filter Lists Edit, Zone WAF Edit, Zone Read.
 */
final class Cloudflare
{
    public const API = 'https://api.cloudflare.com/client/v4';

    public const LIST_NAME = 'porro_blocklist';

    public const RULE_DESCRIPTION = 'Porro blocklist';

    public const EXPRESSION = 'ip.src in $porro_blocklist';

    public const PHASE = 'http_request_firewall_custom';

    /** Polls of an add or delete before giving up; a second apart. */
    public const POLLS = 30;

    private readonly Closure $sleep;

    /**
     * @param  Closure(string $method, string $url, array<string, string> $headers, string|null $body, int $timeout, int $maxBytes): array{0: int, 1: string}  $http
     * @param  (Closure(int $seconds): void)|null  $sleep
     */
    public function __construct(
        private readonly string $token,
        private readonly Closure $http,
        ?Closure $sleep = null,
        private readonly int $timeout = 15,
    ) {
        $this->sleep = $sleep ?? fn (int $seconds) => sleep($seconds);
    }

    /**
     * @throws CloudflareError when the token isn't active
     */
    public function verify(): void
    {
        $result = $this->request('GET', '/user/tokens/verify');

        if (($result['status'] ?? null) !== 'active') {
            throw new CloudflareError('This Cloudflare token isn’t active. Create a new one with the permissions listed.');
        }
    }

    /**
     * The zone serving $host: its own name first, then each parent domain,
     * so "www.example.co.uk" finds the "example.co.uk" zone.
     *
     * @return array{id: string, name: string, account: string}
     *
     * @throws CloudflareError when no zone this token can read serves it
     */
    public function zoneFor(string $host): array
    {
        $labels = explode('.', strtolower(trim($host, '.')));

        while (count($labels) >= 2) {
            $name = implode('.', $labels);
            $zones = $this->request('GET', '/zones?'.http_build_query(['name' => $name, 'status' => 'active']));

            if (is_array($zones[0] ?? null) && isset($zones[0]['id'], $zones[0]['account']['id'])) {
                return ['id' => (string) $zones[0]['id'], 'name' => (string) $zones[0]['name'], 'account' => (string) $zones[0]['account']['id']];
            }

            array_shift($labels);
        }

        throw new CloudflareError("No active Cloudflare zone this token can read serves {$host}. Check the token has Zone Read for it, and that the site is proxied through Cloudflare.");
    }

    /**
     * Finds or creates the list and the rule. Safe to run again: it finds
     * what's already there by name.
     *
     * @return array{account: string, zone: string, zone_name: string, list: string, ruleset: string, rule: string}
     */
    public function connect(string $host): array
    {
        $zone = $this->zoneFor($host);
        $list = $this->ensureList($zone['account']);
        [$ruleset, $rule] = $this->ensureRule($zone['id']);

        return ['account' => $zone['account'], 'zone' => $zone['id'], 'zone_name' => $zone['name'], 'list' => $list, 'ruleset' => $ruleset, 'rule' => $rule];
    }

    /**
     * Makes this site's items in the list match its blocklist.
     *
     * @param  array{account: string, list: string}  $connection
     * @param  list<Entry>  $entries  active blocks
     * @return array{added: int, removed: int, shared: int} shared: blocked by another site's item already
     */
    public function sync(array $connection, string $siteId, array $entries): array
    {
        $prefix = self::prefix($siteId);
        $mine = [];
        $theirs = [];

        foreach ($this->items($connection['account'], $connection['list']) as $item) {
            $ip = self::normalise((string) ($item['ip'] ?? ''));

            if (str_starts_with((string) ($item['comment'] ?? ''), $prefix)) {
                $mine[$ip] = (string) $item['id'];
            } else {
                $theirs[$ip] = true;
            }
        }

        $wanted = [];

        foreach ($entries as $entry) {
            $ip = self::normalise($entry->cidr);

            if ($ip !== '') {
                $wanted[$ip] = $entry;
            }
        }

        $add = [];
        $shared = 0;

        foreach ($wanted as $ip => $entry) {
            if (isset($mine[$ip])) {
                continue;
            }

            if (isset($theirs[$ip])) {
                $shared++;

                continue;
            }

            $add[] = ['ip' => $ip, 'comment' => self::comment($siteId, $entry->note)];
        }

        $remove = array_values(array_map(fn (string $id) => ['id' => $id], array_diff_key($mine, $wanted)));

        foreach (array_chunk($add, 1000) as $chunk) {
            $this->await($connection['account'], $this->request('POST', "/accounts/{$connection['account']}/rules/lists/{$connection['list']}/items", $chunk));
        }

        foreach (array_chunk($remove, 1000) as $chunk) {
            $this->await($connection['account'], $this->request('DELETE', "/accounts/{$connection['account']}/rules/lists/{$connection['list']}/items", ['items' => $chunk]));
        }

        return ['added' => count($add), 'removed' => count($remove), 'shared' => $shared];
    }

    /**
     * Removes this site's items and the zone's rule. The list itself goes
     * only when nothing else is left in it.
     *
     * @param  array{account: string, zone: string, list: string, ruleset: string, rule: string}  $connection
     */
    public function disconnect(array $connection, string $siteId): void
    {
        $this->sync($connection, $siteId, []);

        try {
            $this->request('DELETE', "/zones/{$connection['zone']}/rulesets/{$connection['ruleset']}/rules/{$connection['rule']}");
        } catch (CloudflareError $e) {
            if ($e->status !== 404) {
                throw $e;
            }
        }

        if ($this->items($connection['account'], $connection['list']) === []) {
            $this->request('DELETE', "/accounts/{$connection['account']}/rules/lists/{$connection['list']}");
        }
    }

    /**
     * Cloudflare IP Intelligence: country, network and its type, and any
     * risk categories. Needs Account → Intel → Read on the token; on most
     * plans that may be unavailable, so callers fall back to radar().
     *
     * @return array{country: string|null, asn: int|null, network: string|null, network_type: string|null, risks: list<string>}
     *
     * @throws CloudflareError
     */
    public function intel(string $account, string $ip): array
    {
        $param = Cidr::parse($ip)->isV4() ? 'ipv4' : 'ipv6';
        $result = $this->request('GET', "/accounts/{$account}/intel/ip?".http_build_query([$param => $ip]));
        $row = is_array($result[0] ?? null) ? $result[0] : (is_array($result) ? $result : []);
        $network = is_array($row['belongs_to_ref'] ?? null) ? $row['belongs_to_ref'] : [];

        return [
            'country' => Recorder::country(is_string($network['country'] ?? null) ? $network['country'] : null),
            'asn' => is_numeric($network['value'] ?? null) ? (int) $network['value'] : null,
            'network' => is_string($network['description'] ?? null) ? $network['description'] : null,
            'network_type' => is_string($network['type'] ?? null) ? $network['type'] : null,
            'risks' => array_values(array_filter(array_map(fn ($r) => is_array($r) && is_string($r['name'] ?? null) ? $r['name'] : null, (array) ($row['risk_types'] ?? [])))),
        ];
    }

    /**
     * Cloudflare Radar: network and location only, with any token.
     *
     * @return array{country: string|null, asn: int|null, network: string|null}
     *
     * @throws CloudflareError
     */
    public function radar(string $ip): array
    {
        $row = (array) ($this->request('GET', '/radar/entities/ip?'.http_build_query(['ip' => $ip]))['ip'] ?? []);

        return [
            'country' => Recorder::country(is_string($row['location'] ?? null) ? $row['location'] : null),
            'asn' => is_numeric($row['asn'] ?? null) ? (int) $row['asn'] : null,
            'network' => is_string($row['asnOrgName'] ?? null) ? $row['asnOrgName'] : (is_string($row['asnName'] ?? null) ? $row['asnName'] : null),
        ];
    }

    public static function prefix(string $siteId): string
    {
        return 'porro:'.$siteId.':';
    }

    /**
     * "porro:{site}:{reason}", kept short: Cloudflare shows it in its dashboard.
     */
    public static function comment(string $siteId, string $note): string
    {
        $note = trim((string) preg_replace('/\s+/', ' ', $note));

        return self::prefix($siteId).(strlen($note) > 80 ? substr($note, 0, 79).'…' : $note);
    }

    /**
     * The form Cloudflare stores, so items compare equal: lower case,
     * compressed IPv6, and a bare address rather than a /32 or /128.
     */
    public static function normalise(string $ip): string
    {
        $cidr = Cidr::tryParse($ip);

        return $cidr === null ? '' : (string) $cidr;
    }

    private function ensureList(string $account): string
    {
        foreach ($this->request('GET', "/accounts/{$account}/rules/lists") as $list) {
            if (($list['name'] ?? null) === self::LIST_NAME && ($list['kind'] ?? null) === 'ip') {
                return (string) $list['id'];
            }
        }

        try {
            $list = $this->request('POST', "/accounts/{$account}/rules/lists", [
                'name' => self::LIST_NAME,
                'kind' => 'ip',
                'description' => 'Managed by Porro. Each site adds only its own items.',
            ]);
        } catch (CloudflareError $e) {
            throw new CloudflareError('Cloudflare couldn’t create the porro_blocklist list: '.$e->getMessage().' The Free plan allows one custom list per account; if yours is already used, block with nginx or in the app instead.', $e->status, $e->cloudflareCode);
        }

        return (string) $list['id'];
    }

    /**
     * @return array{0: string, 1: string} ruleset id, rule id
     */
    private function ensureRule(string $zone): array
    {
        $rule = ['action' => 'block', 'expression' => self::EXPRESSION, 'description' => self::RULE_DESCRIPTION, 'enabled' => true];

        try {
            $ruleset = $this->request('GET', "/zones/{$zone}/rulesets/phases/".self::PHASE.'/entrypoint');
        } catch (CloudflareError $e) {
            if ($e->status !== 404) {
                throw $e;
            }

            // No custom rules on this zone yet: start the phase with ours.
            $ruleset = $this->request('POST', "/zones/{$zone}/rulesets", [
                'name' => 'default',
                'kind' => 'zone',
                'phase' => self::PHASE,
                'rules' => [$rule],
            ]);

            return [(string) $ruleset['id'], (string) $this->ours($ruleset)['id']];
        }

        if (($existing = $this->ours($ruleset)) !== null) {
            return [(string) $ruleset['id'], (string) $existing['id']];
        }

        // Added alongside the zone's own rules. Never PUT the entrypoint:
        // that replaces every rule in it.
        $updated = $this->request('POST', "/zones/{$zone}/rulesets/{$ruleset['id']}/rules", $rule);

        return [(string) $ruleset['id'], (string) $this->ours($updated)['id']];
    }

    /**
     * @param  array<string, mixed>  $ruleset
     * @return array<string, mixed>|null
     */
    private function ours(array $ruleset): ?array
    {
        foreach ($ruleset['rules'] ?? [] as $rule) {
            if (($rule['expression'] ?? null) === self::EXPRESSION || ($rule['description'] ?? null) === self::RULE_DESCRIPTION) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function items(string $account, string $list): array
    {
        $items = [];
        $cursor = null;

        do {
            $query = http_build_query(array_filter(['per_page' => 500, 'cursor' => $cursor]));
            [$result, $info] = $this->request('GET', "/accounts/{$account}/rules/lists/{$list}/items?{$query}", withInfo: true);
            array_push($items, ...array_values(array_filter((array) $result, 'is_array')));
            $cursor = $info['cursors']['after'] ?? null;
        } while (is_string($cursor) && $cursor !== '');

        return $items;
    }

    /**
     * Waits for an add or delete to finish.
     *
     * @param  array<string, mixed>  $result
     */
    private function await(string $account, array $result): void
    {
        $operation = $result['operation_id'] ?? null;

        if (! is_string($operation)) {
            return;
        }

        for ($i = 0; $i < self::POLLS; $i++) {
            $status = $this->request('GET', "/accounts/{$account}/rules/lists/bulk_operations/{$operation}");

            if (($status['status'] ?? null) === 'completed') {
                return;
            }

            if (($status['status'] ?? null) === 'failed') {
                throw new CloudflareError('Cloudflare couldn’t update the list: '.($status['error'] ?? 'unknown error'));
            }

            ($this->sleep)(1);
        }

        throw new CloudflareError('Cloudflare is still updating the list. It will be checked again on the next sync.');
    }

    /**
     * @param  array<mixed>|null  $body
     * @return ($withInfo is true ? array{0: mixed, 1: array<string, mixed>} : mixed)
     */
    private function request(string $method, string $path, ?array $body = null, bool $withInfo = false): mixed
    {
        try {
            [$status, $response] = ($this->http)($method, self::API.$path, [
                'Authorization' => 'Bearer '.$this->token,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ], $body === null ? null : json_encode($body, JSON_UNESCAPED_SLASHES), $this->timeout, 10_000_000);
        } catch (Throwable $e) {
            throw new CloudflareError('Couldn’t reach Cloudflare: '.$e->getMessage());
        }

        $data = json_decode((string) $response, true);

        if ($status < 200 || $status >= 300 || ! is_array($data) || ($data['success'] ?? false) !== true) {
            $error = is_array($data['errors'][0] ?? null) ? $data['errors'][0] : [];

            throw new CloudflareError(
                match (true) {
                    $status === 0 => 'Couldn’t reach Cloudflare.',
                    $status === 401, $status === 403 => 'Cloudflare refused the token'.(isset($error['message']) ? ": {$error['message']}" : '').'. Check it has Account Filter Lists Edit, Zone WAF Edit and Zone Read.',
                    default => (string) ($error['message'] ?? "Cloudflare answered {$status}."),
                },
                $status,
                isset($error['code']) ? (int) $error['code'] : null,
            );
        }

        return $withInfo ? [$data['result'] ?? [], (array) ($data['result_info'] ?? [])] : ($data['result'] ?? []);
    }
}
