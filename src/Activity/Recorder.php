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
     * @param  Closure(string $key, int $ttl): mixed  $increment  adds 1, creating the key with $ttl when missing
     * @param  string  $secret  the app's own key, so username hashes can't be matched elsewhere
     * @param  (Closure(string $ip): bool)|null  $safelisted
     * @param  array<string, int>  $thresholds
     */
    public function __construct(
        private readonly Closure $get,
        private readonly Closure $put,
        private readonly Closure $increment,
        private readonly ProtectedRanges $protected,
        private readonly string $secret,
        private readonly ?Closure $safelisted = null,
        array $thresholds = [],
    ) {
        $this->thresholds = $thresholds + self::THRESHOLDS;
    }

    /**
     * @param  string|null  $country  two-letter code the edge already knows, e.g. Cloudflare's CF-IPCountry
     */
    public function record(string $ip, string $signal, string $method, string $path, int $status, ?string $username = null, ?int $at = null, ?string $country = null, ?string $userAgent = null): void
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

            ($this->increment)($this->key("{$hour}:t:{$signal}"), self::TTL);

            if ($this->safelisted !== null && ($this->safelisted)($ip)) {
                return;
            }

            $this->touch($hour, $ip, $signal, $method, $path, $status, $username, $at, self::country($country), $userAgent);
        } catch (Throwable) {
            // Fail open.
        }
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

    private function touch(string $hour, string $ip, string $signal, string $method, string $path, int $status, ?string $username, int $at, ?string $country, ?string $userAgent = null): void
    {
        $key = "{$hour}:ip:{$ip}";
        $record = $this->read($key);
        $isNew = $record === [];
        $slot = (int) (((int) gmdate('i', $at)) / 10);

        $record['c'][$signal] = ($record['c'][$signal] ?? 0) + 1;
        $record['s'][$slot][$signal] = ($record['s'][$slot][$signal] ?? 0) + 1;
        $record['m'] = strtoupper($method);
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
        array_unshift($recent, [strtoupper($method), $path, $status, $at]);
        $record['r'] = array_slice($recent, 0, self::RECENT_CAP);

        if ($signal === self::LOGIN_FAILED && $username !== null && $username !== '' && count($record['u'] ?? []) < self::USERS_CAP) {
            $record['u'][$this->userHash($username)] = 1;
        }

        ($this->put)($this->key($key), $record, self::TTL);

        if ($isNew) {
            $index = $this->read("{$hour}:i");

            if (count($index) < self::INDEX_CAP && ! in_array($ip, $index, true)) {
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
