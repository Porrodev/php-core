<?php

/**
 * A valid site key and its public key, as Porro would issue it.
 *
 * @return array{token: string, public: string, site: string}
 */
function siteKey(): array
{
    $site = '01JABCDEFGHJKMNPQRSTVWXYZ0';
    $seed = random_bytes(32);
    $pair = sodium_crypto_sign_seed_keypair($seed);

    return [
        'token' => 'porro_'.strtolower($site).'_'.rtrim(strtr(base64_encode($seed), '+/', '-_'), '='),
        'public' => sodium_crypto_sign_publickey($pair),
        'site' => $site,
    ];
}

/**
 * @param  array<string, string>  $headers
 */
function signatureIsValid(array $headers, string $body, string $publicKey, string $method = 'POST', string $path = '/api/v1/reports'): bool
{
    $message = "connector-v1\n{$method}\n{$path}\n".$headers['X-Porro-Timestamp']."\n".$headers['X-Porro-Nonce']."\n".hash('sha256', $body);

    return sodium_crypto_sign_verify_detached(base64_decode($headers['X-Porro-Signature']), $message, $publicKey);
}
