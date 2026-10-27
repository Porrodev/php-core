<?php

namespace Porro\Core\Activity;

use Closure;

/**
 * Orders flagged IPs by how worrying they are, once what's known about
 * them is counted: a Spamhaus-listed network is worse than its request
 * count alone says, a research scanner (Censys, Shodan) is noise that
 * probes everyone and goes last.
 */
final class Ranking
{
    /** Multipliers on an IP's score. They stack. */
    public const BOOSTS = [
        IpDetails::SPAMHAUS => 3.0,
        IpDetails::TOR => 1.5,
        IpDetails::FAKE_CRAWLER => 1.5,
    ];

    /** Cloudflare risk categories that double the score. */
    public const RISKS = ['botnet', 'anonymizer', 'malware', 'command and control', 'phishing'];

    /** A hosting network trying passwords is a bot, not a forgetful person. */
    public const HOSTING_LOGINS = 1.5;

    /**
     * @param  list<FlaggedIp>  $flagged
     * @param  Closure(FlaggedIp): array{badges: list<string>, risks: list<string>, network_type: string|null}  $known
     * @return list<FlaggedIp> worst first, research scanners last
     */
    public static function apply(array $flagged, Closure $known): array
    {
        $ranked = array_map(function (FlaggedIp $ip) use ($known) {
            $info = $known($ip);
            $badges = $info['badges'];

            if (array_intersect(array_map('strtolower', $info['risks']), self::RISKS)) {
                $badges[] = 'risk';
            }

            return $ip->withRanking(array_values(array_unique($badges)), round($ip->score * self::multiplier($ip, $info), 1));
        }, $flagged);

        usort($ranked, fn (FlaggedIp $a, FlaggedIp $b) => [self::isScanner($a), -$a->ranking(), -$a->lastSeen] <=> [self::isScanner($b), -$b->ranking(), -$b->lastSeen]);

        return $ranked;
    }

    public static function isScanner(FlaggedIp $ip): bool
    {
        return in_array(IpDetails::SCANNER, $ip->badges, true);
    }

    /**
     * @param  array{badges: list<string>, risks: list<string>, network_type: string|null}  $info
     */
    private static function multiplier(FlaggedIp $ip, array $info): float
    {
        $multiplier = 1.0;

        foreach (self::BOOSTS as $badge => $boost) {
            if (in_array($badge, $info['badges'], true)) {
                $multiplier *= $boost;
            }
        }

        if (array_intersect(array_map('strtolower', $info['risks']), self::RISKS)) {
            $multiplier *= 2;
        }

        if ($info['network_type'] === 'hosting_provider' && ($ip->counts[Recorder::LOGIN_FAILED] ?? 0) > 0) {
            $multiplier *= self::HOSTING_LOGINS;
        }

        return $multiplier;
    }
}
