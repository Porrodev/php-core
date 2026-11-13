<?php

namespace Porro\Core\Health;

/**
 * Mistakes in how the site sends email: mail that goes nowhere, mail
 * handed to the server's own sendmail, and a sender address that isn't
 * the site's. Only a problem in production, and nothing here touches the
 * network: the connector passes what the site's mail settings say.
 */
final class MailChecks
{
    /** Transports that keep the mail on the server and send nothing. */
    private const NOT_SENT = ['log', 'array', 'null'];

    /** Transports that hand mail to the server's own mail program. */
    private const SERVER = ['sendmail', 'mail'];

    /** SMTP hosts that catch mail for testing rather than deliver it. */
    private const TEST_INBOXES = ['mailpit', 'mailhog', 'maildev', 'mailcatcher', 'sandbox.smtp.mailtrap.io', 'smtp.mailtrap.io', 'smtp.ethereal.email'];

    private const LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'];

    private const PLACEHOLDER_DOMAINS = ['example.com', 'example.org', 'example.net', 'domain.com', 'yourdomain.com', 'localhost'];

    /**
     * Free mailbox domains, and the SMTP hosts allowed to send as them.
     * Sent through anything else, their DMARC policy has the mail rejected.
     */
    private const MAILBOXES = [
        'gmail.com' => ['gmail.com', 'google.com'],
        'googlemail.com' => ['gmail.com', 'google.com'],
        'outlook.com' => ['outlook.com', 'office365.com', 'live.com'],
        'hotmail.com' => ['outlook.com', 'office365.com', 'live.com'],
        'hotmail.co.uk' => ['outlook.com', 'office365.com', 'live.com'],
        'live.com' => ['outlook.com', 'office365.com', 'live.com'],
        'live.co.uk' => ['outlook.com', 'office365.com', 'live.com'],
        'msn.com' => ['outlook.com', 'office365.com', 'live.com'],
        'yahoo.com' => ['yahoo.com'],
        'yahoo.co.uk' => ['yahoo.com'],
        'aol.com' => ['aol.com'],
        'icloud.com' => ['me.com', 'icloud.com'],
        'me.com' => ['me.com', 'icloud.com'],
        'btinternet.com' => ['btinternet.com'],
    ];

    /** Second-level labels that are part of the suffix under a country code, e.g. co.uk. */
    private const SECOND_LEVEL = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ltd', 'plc', 'me', 'nom', 'sch', 'nhs'];

    /**
     * transport is the mailer in use ("smtp", "sendmail", "log", "ses"…),
     * host the SMTP host, from the default sender address, and site the
     * site's URL or host.
     *
     * @param  array{transport?: string|null, host?: string|null, from?: string|null, site?: string|null, environment?: string|null}  $mail
     * @param  string  $where  where to change it, e.g. "MAIL_MAILER in .env"
     * @return list<Issue>
     */
    public function check(array $mail, string $where): array
    {
        if (! self::production($mail['environment'] ?? null)) {
            return [];
        }

        $transport = strtolower(trim((string) ($mail['transport'] ?? '')));
        $host = strtolower(trim((string) ($mail['host'] ?? '')));

        return array_values(array_filter([
            $this->transport($transport, $host, $where),
            $this->sender(strtolower(trim((string) ($mail['from'] ?? ''))), self::host($mail['site'] ?? null), $transport, $host),
        ]));
    }

    public static function production(mixed $environment): bool
    {
        return in_array($environment, ['production', 'prod', 'live'], true);
    }

    private function transport(string $transport, string $host, string $where): ?Issue
    {
        if (in_array($transport, self::NOT_SENT, true)) {
            return new Issue(
                'mail_not_sent',
                Issue::WARNING,
                'Email isn’t being sent',
                "The “{$transport}” mailer keeps every email on the server, so password resets, form notifications and receipts never arrive · set a real mailer · {$where}",
            );
        }

        if ($transport === 'smtp' && self::testInbox($host)) {
            return new Issue(
                'mail_not_sent',
                Issue::WARNING,
                'Email goes to a test inbox',
                "SMTP points at {$host}, which catches mail for testing rather than delivering it · set a real mailer · {$where}",
            );
        }

        if (in_array($transport, self::SERVER, true) || ($transport === 'smtp' && in_array($host, self::LOCAL_HOSTS, true))) {
            $via = $transport === 'smtp' ? "SMTP on {$host}" : ($transport === 'mail' ? 'PHP’s mail()' : 'sendmail');

            return new Issue(
                'mail_server_sendmail',
                Issue::WARNING,
                'Email is sent by the web server itself',
                "Mail goes out through {$via}. Web servers have no sending reputation and usually no SPF or DKIM, so mail lands in spam or is dropped without an error · send through an email service or your mailbox provider’s SMTP · {$where}",
            );
        }

        return null;
    }

    private function sender(string $from, ?string $site, string $transport, string $host): ?Issue
    {
        $domain = str_contains($from, '@') ? substr($from, strrpos($from, '@') + 1) : '';

        if ($domain === '') {
            return new Issue('mail_sender', Issue::WARNING, 'No sender address set', 'Email goes out without a proper From address, which most providers reject or mark as spam');
        }

        if (in_array($domain, self::PLACEHOLDER_DOMAINS, true)) {
            return new Issue('mail_sender', Issue::WARNING, 'Sender address is still the placeholder', "Email is sent from {$from} · use an address on the site’s own domain");
        }

        if (isset(self::MAILBOXES[$domain]) && ! ($transport === 'smtp' && self::under($host, self::MAILBOXES[$domain]))) {
            return new Issue(
                'mail_sender',
                Issue::WARNING,
                "Sender address is a {$domain} mailbox",
                "Email is sent from {$from}, but not through {$domain}’s own servers, so it fails DMARC and is rejected or marked as spam · use an address on the site’s own domain",
            );
        }

        if ($site === null || isset(self::MAILBOXES[$domain]) || self::registrable($domain) === self::registrable($site)) {
            return null;
        }

        return new Issue(
            'mail_sender',
            Issue::NOTICE,
            'Sender address isn’t on the site’s domain',
            "Email is sent from {$from}, but the site is {$site} · fine if that’s deliberate and {$domain} is set up for your mail service (SPF and DKIM); if not, use an address on the site’s domain",
        );
    }

    private static function testInbox(string $host): bool
    {
        return in_array($host, self::TEST_INBOXES, true);
    }

    /**
     * Whether a host is one of these names or a subdomain of one.
     *
     * @param  list<string>  $names
     */
    private static function under(string $host, array $names): bool
    {
        foreach ($names as $name) {
            if ($host === $name || str_ends_with($host, '.'.$name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The site's public host, or null when it has none worth comparing
     * (no URL, an IP address, localhost, a .test domain).
     */
    private static function host(mixed $site): ?string
    {
        if (! is_string($site) || trim($site) === '') {
            return null;
        }

        $site = strtolower(trim($site));
        $host = parse_url(str_contains($site, '://') ? $site : "https://{$site}", PHP_URL_HOST);

        if (! is_string($host) || ! str_contains($host, '.') || filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
            return null;
        }

        $host = preg_replace('/^www\./', '', $host);

        return self::under($host, ['test', 'local', 'localhost', 'invalid', 'example']) ? null : $host;
    }

    /**
     * The domain someone registered: acme.com for mail.acme.com, and
     * acme.co.uk for shop.acme.co.uk. A rule of thumb rather than the
     * full public suffix list, which is enough to tell "same company"
     * from "somewhere else".
     */
    private static function registrable(string $host): string
    {
        $labels = explode('.', $host);
        $count = count($labels);
        $keep = $count >= 3 && strlen($labels[$count - 1]) === 2 && in_array($labels[$count - 2], self::SECOND_LEVEL, true) ? 3 : 2;

        return implode('.', array_slice($labels, -$keep));
    }
}
