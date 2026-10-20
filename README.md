# porro/php-core

Shared core for the [Porro](https://porro.dev) connectors: parsing site keys, signing reports, reading `composer.lock` and sending reports to Porro.

You don't install this directly. It comes with a connector:

| Connector | For |
|---|---|
| [`porro/laravel-connector`](https://github.com/Porrodev/laravel-connector) | Laravel 11–13 |
| [`porro/filament-connector`](https://github.com/Porrodev/filament-connector) | Filament 3–5 |
| [`porro/statamic-connector`](https://github.com/Porrodev/statamic-connector) | Statamic 5–6 |

## How reports are signed

A site key looks like `porro_{site id}_{seed}`. The seed is the private half of an Ed25519 key pair; Porro stores only the public half. Each report is signed over:

```
{timestamp}\n{nonce}\n{sha256 of body}
```

and sent with `X-Porro-Site`, `X-Porro-Timestamp`, `X-Porro-Nonce` and `X-Porro-Signature` headers. Porro rejects a report outside a 5-minute window or if it has seen the nonce before. If `ext-sodium` isn't available, `paragonie/sodium_compat` provides it in pure PHP.

## Developing

```bash
composer install
composer test
```

## Security

Please email security@porro.dev rather than opening an issue. We reply within one working day.

## License

MIT
