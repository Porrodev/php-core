<?php

namespace Porro\Core\Activity;

use Closure;
use Throwable;

/**
 * Counts suspicious requests in the connector's cache, in hourly buckets
 * kept for 48 hours. Only signal events are recorded (a probe, a failed
 * login, a 404, a form POST), so ordinary page views cost nothing.
 *
 * Raw IPs stay in this cache and nowhere else. Usernames are kept only
 * as keyed hashes, enough to count how many accounts an IP tried.
 *
 * Every write fails open: a broken cache must never break a page.
 */
final class Recorder
{
    public const PROBE = 'probe';

    public const LOGIN_FAILED = 'login_failed';

    public const NOT_FOUND = 'not_found';

    public const POST_FLOOD = 'post_flood';

    public const SIGNALS = [self::PROBE, self::LOGIN_FAILED, self::NOT_FOUND, self::POST_FLOOD];

    public const TTL = 172800;

    public const PREFIX = 'porro:activity:';

    /** IPs indexed per hour; more still count towards the totals. */
    public const INDEX_CAP = 500;

    public const RECENT_CAP = 10;

    public const USERS_CAP = 20;

    public const EXPOSED_CAP = 20;

    /** Per-IP lists kept short, so one hour's record stays small. */
    public const PATHS_CAP = 25;

    public const AGENTS_CAP = 5;

    public const HOSTS_CAP = 5;

    /** Flagged IPs whose every request is counted, for the IP page. */
    public const WATCH_CAP = 500;

    /**
     * Past this many requests from one IP in an hour, only one in
     * FLOOD_SAMPLE is written, counted FLOOD_SAMPLE times: a flood costs a
     * tenth of the writes, and its counts become close estimates. Ten
     * times further on, one in a hundred.
     */
    public const FLOOD_AFTER = 300;

    public const FLOOD_SAMPLE = 10;

    /** Methods kept by name; anything else a client sends is "OTHER". */
    public const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'];

    /** How much each signal adds to an IP's score. */
    public const WEIGHTS = [self::PROBE => 5, self::LOGIN_FAILED => 3, self::POST_FLOOD => 2, self::NOT_FOUND => 1];

    /**
     * When an IP is flagged. probe and login_failed count per hour,
     * not_found and post_flood per 10 minutes.
     */
    public const THRESHOLDS = [
        self::PROBE => 3,
        self::LOGIN_FAILED => 10,
        'login_users' => 5,
        self::NOT_FOUND => 60,
        self::POST_FLOOD => 20,
    ];

    /** @var array<string, int> */
    private readonly array $thresholds;

    /**
     * @param  Closure(string $key): mixed  $get
     * @param  Closure(string $key, mixed $value, int $ttl): mixed  $put
     * @param  Closure(string $key, int $ttl, int $by): mixed  $increment  adds $by (1 unless sampling), creating the key with $ttl when missing
     * @param  string  $secret  the app's own key, so username hashes can't be matched elsewhere
     * @param  (Closure(string $ip): bool)|null  $safelisted
     * @param  array<string, int>  $thresholds
     * @param  (Closure(list<string> $keys): array<string, mixed>)|null  $many  reads several keys in one go, when the store can
     * @param  (Closure(int $min, int $max): int)|null  $random
     */
    public function __construct(
        private readonly Closure $get,
        private readonly Closure $put,
        private readonly Closure $increment,
        private readonly ProtectedRanges $protected,
        private readonly string $secret,
        private readonly ?Closure $safelisted = null,
        array $thresholds = [],
        private readonly ?Closure $many = null,
        ?Closure $random = null,
    ) {
        $this->thresholds = $thresholds + self::THRESHOLDS;
        $this->random = $random ?? fn (int $min, int $max) => random_int($min, $max);
    }

    private readonly Closure $random;

    /**
     * @param  string|null  $country  two-letter code the edge already knows, e.g. Cloudflare's CF-IPCountry
     * @param  string|null  $category  for a probe, what it was after (a Probes category)
     * @param  bool|null  $proxied  true when it came through Cloudflare, false when straight to the server
     */
    public function record(string $ip, string $signal, string $method, string $path, int $status, ?string $username = null, ?int $at = null, ?string $country = null, ?string $userAgent = null, ?string $category = null, ?string $host = null, ?bool $proxied = null): void
    {
        if (! in_array($signal, self::SIGNALS, true) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $at ??= time();
        $hour = gmdate('YmdH', $at);

        try {
            $source = $this->protected->match($ip);

            if ($source !== null) {
                // Proxies and private addresses here mean the site can't see
                // visitor IPs; Forge and config ranges are simply skipped.
                if (in_array($source, [ProtectedRanges::CLOUDFLARE, ProtectedRanges::RESERVED], true)) {
                    ($this->increment)($this->key("{$hour}:t:proxied"), self::TTL);
                }

                return;
            }

            $record = $this->read("{$hour}:ip:{$ip}");
            $weight = $this->weight($record);

            if ($weight === 0) {
                return;
            }

            ($this->increment)($this->key("{$hour}:t:{$signal}"), self::TTL, $weight);

            if ($this->safelisted !== null && ($this->safelisted)($ip)) {
                return;
            }

            $this->touch($hour, $ip, $signal, $method, $path, $status, $username, $at, self::country($country), $userAgent, compact('category', 'host', 'proxied'), $record, $weight);
        } catch (Throwable) {
            // Fail open.
        }
    }

    /**
     * Any other request from an IP already flagged (see watched()), so its
     * page can say how many requests it made. Never counts towards flagging.
     */
    public function seen(string $ip, string $method, string $path, int $status, ?string $host = null, ?string $userAgent = null, ?bool $proxied = null, ?int $at = null): void
    {
        $this->note($ip, $method, $path, $status, $host, $userAgent, $proxied, $at, false);
    }

    /**
     * A request a block turned away before the app ran.
     */
    public function turnedAway(string $ip, string $method, string $path, ?string $host = null, ?string $userAgent = null, ?bool $proxied = null, ?int $at = null): void
    {
        $this->note($ip, $method, $path, 403, $host, $userAgent, $proxied, $at, true);
    }

    /**
     * IPs flagged in the last 48 hours, whose every request is counted.
     *
     * @return list<string>
     */
    public function watched(?int $now = null): array
    {
        $since = ($now ?? time()) - self::TTL;

        return array_values(array_map('strval', array_keys(array_filter($this->read('watch'), fn ($at) => (int) $at > $since))));
    }

    /**
     * Everything recorded for one IP over the last hours, flagged or not,
     * or null when nothing was.
     */
    public function history(string $ip, int $hours = 48, ?int $now = null): ?IpActivity
    {
        $now ??= time();
        $counts = array_fill_keys(self::SIGNALS, 0);
        $sum = ['q' => 0, 'b' => 0, 'po' => 0, 'edge' => 0, 'direct' => 0];
        $maps = ['pk' => [], 'ag' => [], 'hs' => [], 'mt' => [], 'sc' => []];
        $paths = [];
        $hourly = [];
        $recent = [];
        [$first, $last, $flagged, $country, $estimated] = [PHP_INT_MAX, 0, false, null, false];

        $keys = [];

        for ($i = $hours - 1; $i >= 0; $i--) {
            $hour = gmdate('YmdH', $now - $i * 3600);
            $keys[$hour] = "{$hour}:ip:{$ip}";
        }

        $records = $this->readMany($keys);

        foreach ($keys as $hour => $key) {
            $record = $records[$hour];

            if ($record === []) {
                continue;
            }

            foreach ($record['c'] ?? [] as $signal => $n) {
                $counts[$signal] = ($counts[$signal] ?? 0) + (int) $n;
            }

            // Records from before request counting only have signals.
            $requests = (int) ($record['q'] ?? array_sum($record['c'] ?? []));
            $hourly[$hour] = $requests;
            $sum['q'] += $requests;
            $sum['b'] += (int) ($record['b'] ?? 0);
            $sum['po'] += (int) ($record['po'] ?? 0);
            $sum['edge'] += (int) ($record['vx']['edge'] ?? 0);
            $sum['direct'] += (int) ($record['vx']['direct'] ?? 0);

            foreach ($maps as $name => $map) {
                foreach ($record[$name] ?? [] as $key => $n) {
                    $maps[$name][$key] = ($map[$key] ?? 0) + (int) $n;
                }
            }

            foreach ($record['pc'] ?? [] as $path => [$n, $status]) {
                $paths[$path] = [($paths[$path][0] ?? 0) + (int) $n, (int) $status];
            }

            $first = min($first, (int) ($record['f'] ?? $record['t'] ?? $first));
            $last = max($last, (int) ($record['t'] ?? 0));
            $country = $record['cc'] ?? $country;
            $flagged = $flagged || $this->crosses($record);
            $estimated = $estimated || ! empty($record['e']);
            $recent = array_merge($record['r'] ?? [], $recent);
        }

        if ($hourly === []) {
            return null;
        }

        usort($recent, fn ($a, $b) => $b[3] <=> $a[3]);
        uasort($paths, fn ($a, $b) => $b[0] <=> $a[0]);
        $shown = array_slice($paths, 0, self::PATHS_CAP, true);

        foreach ($maps as $name => $map) {
            arsort($map);
            $maps[$name] = $map;
        }

        return new IpActivity(
            ip: $ip,
            counts: $counts,
            requests: $sum['q'],
            turnedAway: $sum['b'],
            firstSeen: $first === PHP_INT_MAX ? $last : $first,
            lastSeen: $last,
            flagged: $flagged,
            hourly: $hourly,
            recent: array_slice($recent, 0, self::RECENT_CAP),
            paths: $shown,
            otherPaths: $sum['po'] + array_sum(array_column(array_slice($paths, self::PATHS_CAP, null, true), 0)),
            categories: $maps['pk'],
            agents: array_slice($maps['ag'], 0, self::AGENTS_CAP, true),
            hosts: array_slice($maps['hs'], 0, self::HOSTS_CAP, true),
            methods: $maps['mt'],
            statuses: $maps['sc'],
            viaCloudflare: $sum['edge'],
            direct: $sum['direct'],
            country: is_string($country) ? $country : null,
            estimated: $estimated,
        );
    }

    /**
     * Notes a secrets or VCS probe the site answered with 2xx.
     */
    public function exposed(string $ip, string $path, int $status, ?int $at = null): void
    {
        try {
            $list = $this->read('exposed');
            $path = Probes::normalise($path);
            $list = array_values(array_filter($list, fn ($e) => ($e['path'] ?? null) !== $path));
            array_unshift($list, ['path' => $path, 'ip' => $ip, 'status' => $status, 'at' => $at ?? time()]);
            ($this->put)($this->key('exposed'), array_slice($list, 0, self::EXPOSED_CAP), self::TTL);
        } catch (Throwable) {
            //
        }
    }

    public function summary(int $hours = 24, ?int $now = null): Summary
    {
        $now ??= time();
        $totals = array_fill_keys(self::SIGNALS, 0);
        $proxied = 0;
        $ips = [];
        $targets = [];

        for ($i = $hours - 1; $i >= 0; $i--) {
            $hour = gmdate('YmdH', $now - $i * 3600);

            foreach (self::SIGNALS as $signal) {
                $totals[$signal] += (int) $this->value("{$hour}:t:{$signal}");
            }

            $proxied += (int) $this->value("{$hour}:t:proxied");

            foreach ($this->read("{$hour}:i") as $ip) {
                $record = $this->read("{$hour}:ip:{$ip}");

                if ($record === []) {
                    continue;
                }

                $ips[$ip] = $this->merge($ips[$ip] ?? null, $record, $hour);

                foreach (array_keys($record['u'] ?? []) as $user) {
                    $targets[$user][$ip] = true;
                }
            }
        }

        $flagged = [];

        foreach ($ips as $ip => $data) {
            if ($data['flagged']) {
                $flagged[] = new FlaggedIp(
                    ip: (string) $ip,
                    counts: $data['c'],
                    users: count($data['u']),
                    lastMethod: $data['m'],
                    lastPath: $data['p'],
                    lastStatus: $data['st'],
                    lastSeen: $data['t'],
                    country: $data['cc'],
                    userAgent: $data['ua'],
                    recent: array_slice($data['r'], 0, self::RECENT_CAP),
                    hourly: $data['h'],
                    score: $this->score($data['c']),
                );
            }
        }

        usort($flagged, fn (FlaggedIp $a, FlaggedIp $b) => [$b->score, $b->lastSeen] <=> [$a->score, $a->lastSeen]);

        $signals = array_sum($totals);

        return new Summary(
            hours: $hours,
            totals: $totals,
            flagged: $flagged,
            proxiedShare: $proxied + $signals > 0 ? $proxied / ($proxied + $signals) : 0.0,
            proxied: $proxied,
            exposed: $this->read('exposed'),
            targets: array_map('count', $targets),
        );
    }

    /**
     * A two-letter country code, upper case, or null. Keeps Cloudflare's
     * T1 (Tor); drops XX (unknown).
     */
    public static function country(?string $code): ?string
    {
        $code = strtoupper(trim((string) $code));

        return preg_match('/^[A-Z][A-Z0-9]$/', $code) && $code !== 'XX' ? $code : null;
    }

    /**
     * The keyed hash a username is stored as. Connectors use the same to
     * show which real account was targeted.
     */
    public function userHash(string $username): string
    {
        return substr(hash_hmac('sha256', strtolower(trim($username)), $this->secret), 0, 16);
    }

    /**
     * @param  array<string, int>  $counts
     */
    public function score(array $counts): int
    {
        $score = 0;

        foreach (self::WEIGHTS as $signal => $weight) {
            $score += ($counts[$signal] ?? 0) * $weight;
        }

        return $score;
    }

    private function note(string $ip, string $method, string $path, int $status, ?string $host, ?string $userAgent, ?bool $proxied, ?int $at, bool $blocked): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $at ??= time();

        try {
            if ($this->protected->match($ip) !== null) {
                return;
            }

            $hour = gmdate('YmdH', $at);
            $record = $this->read("{$hour}:ip:{$ip}");
            $weight = $this->weight($record);

            if ($weight > 0) {
                $this->touch($hour, $ip, null, $method, $path, $status, null, $at, null, $userAgent, compact('host', 'proxied', 'blocked'), $record, $weight);
            }
        } catch (Throwable) {
            // Fail open.
        }
    }

    /**
     * @param  array{category?: ?string, host?: ?string, proxied?: ?bool, blocked?: bool}  $more
     * @param  array<string, mixed>  $record  this hour's record for the IP, as already read
     * @param  int  $weight  how many requests this write stands for (see FLOOD_AFTER)
     */
    private function touch(string $hour, string $ip, ?string $signal, string $method, string $path, int $status, ?string $username, int $at, ?string $country, ?string $userAgent, array $more, array $record, int $weight): void
    {
        $key = "{$hour}:ip:{$ip}";
        $isNew = $record === [];
        $index = [];

        // A full hour (a botnet, or rotating IPv6) still counts towards the
        // totals, but adds no more records.
        if ($isNew) {
            $index = $this->read("{$hour}:i");

            if (count($index) >= self::INDEX_CAP && ! in_array($ip, $index, true)) {
                return;
            }
        }

        $slot = (int) (((int) gmdate('i', $at)) / 10);
        $method = self::method($method);
        $path = substr($path, 0, 200);
        $w = $weight;

        if ($signal !== null) {
            $record['c'][$signal] = ($record['c'][$signal] ?? 0) + $w;
            $record['s'][$slot][$signal] = ($record['s'][$slot][$signal] ?? 0) + $w;
        }

        $record['q'] = ($record['q'] ?? array_sum($record['c'] ?? []) - ($signal !== null ? $w : 0)) + $w;
        $record['f'] = min((int) ($record['f'] ?? $at), $at);
        $record['mt'][$method] = ($record['mt'][$method] ?? 0) + $w;

        if ($w > 1) {
            $record['e'] = true;
        }

        if (! empty($more['blocked'])) {
            $record['b'] = ($record['b'] ?? 0) + $w;
        }

        if ($status > 0) {
            $class = intdiv($status, 100).'xx';
            $record['sc'][$class] = ($record['sc'][$class] ?? 0) + $w;
        }

        if (isset($more['proxied'])) {
            $via = $more['proxied'] ? 'edge' : 'direct';
            $record['vx'][$via] = ($record['vx'][$via] ?? 0) + $w;
        }

        if (! empty($more['category']) && isset(Probes::LABELS[$more['category']])) {
            $record['pk'][$more['category']] = ($record['pk'][$more['category']] ?? 0) + $w;
        }

        if (! empty($more['host'])) {
            $record['hs'] = self::bump($record['hs'] ?? [], strtolower(substr((string) $more['host'], 0, 100)), self::HOSTS_CAP, $w);
        }

        if ($userAgent !== null && $userAgent !== '') {
            $record['ag'] = self::bump($record['ag'] ?? [], substr($userAgent, 0, 200), self::AGENTS_CAP, $w);
        }

        // Each path's count and last status; past the cap, only counted.
        if (isset($record['pc'][$path]) || count($record['pc'] ?? []) < self::PATHS_CAP) {
            $record['pc'][$path] = [($record['pc'][$path][0] ?? 0) + $w, $status];
        } else {
            $record['po'] = ($record['po'] ?? 0) + $w;
        }

        $record['m'] = $method;
        $record['p'] = $path;
        $record['st'] = $status;
        $record['t'] = $at;

        if ($country !== null) {
            $record['cc'] = $country;
        }

        // The last one only, cut short: enough to spot a fake Googlebot.
        if ($userAgent !== null && $userAgent !== '') {
            $record['ua'] = substr($userAgent, 0, 200);
        }

        $recent = $record['r'] ?? [];
        array_unshift($recent, [$method, $path, $status, $at]);
        $record['r'] = array_slice($recent, 0, self::RECENT_CAP);

        if ($signal === self::LOGIN_FAILED && $username !== null && $username !== '' && count($record['u'] ?? []) < self::USERS_CAP) {
            $record['u'][$this->userHash($username)] = 1;
        }

        ($this->put)($this->key($key), $record, self::TTL);

        if ($signal !== null && $this->crosses($record)) {
            $this->watch($ip, $at);
        }

        if ($isNew) {
            if (! in_array($ip, $index, true)) {
                $index[] = $ip;
                ($this->put)($this->key("{$hour}:i"), $index, self::TTL);
            }
        }
    }

    /**
     * @param  array<string, mixed>|null  $into
     * @param  array<string, mixed>  $record
     * @return array<string, mixed>
     */
    private function merge(?array $into, array $record, string $hour): array
    {
        $into ??= ['c' => array_fill_keys(self::SIGNALS, 0), 'u' => [], 'm' => '', 'p' => '', 'st' => 0, 't' => 0, 'cc' => null, 'ua' => null, 'r' => [], 'h' => [], 'flagged' => false];

        $into['cc'] = $record['cc'] ?? $into['cc'];
        $into['ua'] = $record['ua'] ?? $into['ua'];

        foreach ($record['c'] ?? [] as $signal => $n) {
            $into['c'][$signal] = ($into['c'][$signal] ?? 0) + (int) $n;
        }

        $into['u'] += $record['u'] ?? [];
        $into['h'][$hour] = array_sum($record['c'] ?? []);

        if (($record['t'] ?? 0) >= $into['t']) {
            [$into['m'], $into['p'], $into['st'], $into['t']] = [$record['m'] ?? '', $record['p'] ?? '', (int) ($record['st'] ?? 0), (int) $record['t']];
        }

        $recent = array_merge($record['r'] ?? [], $into['r']);
        usort($recent, fn ($a, $b) => $b[3] <=> $a[3]);
        $into['r'] = array_slice($recent, 0, self::RECENT_CAP);

        $into['flagged'] = $into['flagged'] || $this->crosses($record);

        return $into;
    }

    /**
     * @param  array<string, mixed>  $record  one hour of one IP
     */
    private function crosses(array $record): bool
    {
        $c = $record['c'] ?? [];

        if (($c[self::PROBE] ?? 0) >= $this->thresholds[self::PROBE]
            || ($c[self::LOGIN_FAILED] ?? 0) >= $this->thresholds[self::LOGIN_FAILED]
            || count($record['u'] ?? []) >= $this->thresholds['login_users']) {
            return true;
        }

        foreach ($record['s'] ?? [] as $slot) {
            if (($slot[self::NOT_FOUND] ?? 0) >= $this->thresholds[self::NOT_FOUND]
                || ($slot[self::POST_FLOOD] ?? 0) >= $this->thresholds[self::POST_FLOOD]) {
                return true;
            }
        }

        return false;
    }

    private function watch(string $ip, int $at): void
    {
        $list = $this->read('watch');

        if (isset($list[$ip])) {
            return;
        }

        // Kept no longer than the activity it came from.
        $list = array_filter($list, fn ($since) => (int) $since > $at - self::TTL);
        $list[$ip] = $at;
        arsort($list);
        ($this->put)($this->key('watch'), array_slice($list, 0, self::WATCH_CAP, true), self::TTL);
    }

    /**
     * Adds one to a capped count map. Past the cap a new key replaces the
     * least seen, so a long run of one-off values doesn't freeze it.
     *
     * @param  array<string, int>  $map
     * @return array<string, int>
     */
    private static function bump(array $map, string $key, int $cap, int $by = 1): array
    {
        if (! isset($map[$key]) && count($map) >= $cap) {
            asort($map);
            unset($map[array_key_first($map)]);
        }

        $map[$key] = ($map[$key] ?? 0) + $by;

        return $map;
    }

    /**
     * How many requests this write stands for: 1, or once an IP is past
     * FLOOD_AFTER this hour, FLOOD_SAMPLE for one request in FLOOD_SAMPLE
     * and 0 (skip) for the rest.
     *
     * @param  array<string, mixed>  $record
     */
    private function weight(array $record): int
    {
        $requests = (int) ($record['q'] ?? 0);

        if ($requests < self::FLOOD_AFTER) {
            return 1;
        }

        $sample = $requests < self::FLOOD_AFTER * self::FLOOD_SAMPLE ? self::FLOOD_SAMPLE : self::FLOOD_SAMPLE ** 2;

        return ($this->random)(1, $sample) === 1 ? $sample : 0;
    }

    /**
     * A known method by name, anything else as "OTHER": clients can send
     * any token, and Craft honours X-Http-Method-Override.
     */
    public static function method(string $method): string
    {
        $method = strtoupper(substr($method, 0, 10));

        return in_array($method, self::METHODS, true) ? $method : 'OTHER';
    }

    /**
     * @param  array<string, string>  $keys  name => key
     * @return array<string, array<mixed>> name => value, [] when missing
     */
    private function readMany(array $keys): array
    {
        if ($this->many === null) {
            return array_map(fn (string $key) => $this->read($key), $keys);
        }

        try {
            $values = ($this->many)(array_values(array_map(fn (string $key) => $this->key($key), $keys)));
        } catch (Throwable) {
            // One at a time, rather than an empty history.
            return array_map(fn (string $key) => $this->read($key), $keys);
        }

        return array_map(fn (string $key) => is_array($values[$this->key($key)] ?? null) ? $values[$this->key($key)] : [], $keys);
    }

    /**
     * @return array<mixed>
     */
    private function read(string $key): array
    {
        $value = $this->value($key);

        return is_array($value) ? $value : [];
    }

    private function value(string $key): mixed
    {
        try {
            return ($this->get)($this->key($key));
        } catch (Throwable) {
            return null;
        }
    }

    private function key(string $key): string
    {
        return self::PREFIX.$key;
    }
}
