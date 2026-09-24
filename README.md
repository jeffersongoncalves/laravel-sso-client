<div class="filament-hidden">

![Laravel SSO Client](art/jeffersongoncalves-laravel-sso-client.png)

</div>

# Laravel SSO Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-sso-client)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-sso-client/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-sso-client/actions?query=workflow%3ATests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-sso-client/pint.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-sso-client/actions?query=workflow%3Apint+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-sso-client)
[![License](https://img.shields.io/packagist/l/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](LICENSE.md)

SSO client for Laravel apps that authenticate against [`jeffersongoncalves/laravel-sso-server`](https://github.com/jeffersongoncalves/laravel-sso-server): Authorization Code + PKCE login, RS256/JWKS or signed userinfo token validation, local user sync and back-channel Single Logout.

## Compatibility

| Package | PHP | Laravel | laravel-sso-server |
|---------|-----|---------|--------------------|
| 1.x     | 8.2+ | 12.x, 13.x | 1.x |

## Installation

On the **server** app, register this client (prints the `client_id` and `client_secret`):

```bash
php artisan sso-server:client "Billing" https://billing.example.com/sso/callback --slo=https://billing.example.com/sso/slo-webhook
```

On the **client** app:

```bash
composer require jeffersongoncalves/laravel-sso-client
php artisan vendor:publish --tag="laravel-sso-client-config"
```

```dotenv
SSO_SERVER_URL=https://sso.example.com
SSO_CLIENT_ID=<client_id>
SSO_CLIENT_SECRET=<client_secret>
# Optional: the server's sso-server.issuer when it differs from SSO_SERVER_URL
SSO_ISSUER=
# jwks (local, default) or userinfo (asks the server on every login)
SSO_VERIFICATION=jwks
```

The redirect URI sent to the server defaults to this package's callback route and must match the registered one exactly (override with `SSO_REDIRECT_URI`).

## Usage

Protect routes with the `sso.auth` middleware. Guests are sent to the SSO Server and come back to the URL they asked for; sessions revoked by Single Logout are ended here too:

```php
Route::middleware(['web', 'sso.auth'])->group(function () {
    Route::get('/dashboard', DashboardController::class);
});
```

Routes registered by the package (prefix configurable via `sso-client.route.prefix`):

| Method | URI | Name | Purpose |
|--------|-----|------|---------|
| GET  | `/sso/redirect`    | `sso-client.redirect`    | Starts the flow (state + PKCE S256) |
| GET  | `/sso/callback`    | `sso-client.callback`    | Checks state, exchanges the code, logs in |
| POST | `/sso/slo-webhook` | `sso-client.slo-webhook` | Back-channel Single Logout (no session, no CSRF, HMAC-authenticated) |

The server paths (`/sso/authorize`, `/sso/token`, `/sso/userinfo`, `/.well-known/jwks.json`) are configurable in `sso-client.endpoints` to follow the server's route prefix.

### Custom user synchronization

The default synchronizer creates or updates an Eloquent user matched on `sso-client.user.identifier` (email by default), filling the columns mapped in `sso-client.user.attributes` from the server claims (`name` and `email` with the server's default serializer). New users get a random, unusable password.

To link users by the server id instead of the email, add an `sso_id` column and set `'identifier' => 'sso_id'` with `'sso_id' => 'sub'` in the attribute map. To keep users in memory only or map roles, implement the contract and set `sso-client.synchronizer`:

```php
use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;

class RoleAwareSynchronizer implements SsoUserSynchronizerContract
{
    public function synchronize(array $ssoPayload): Authenticatable
    {
        $user = User::updateOrCreate(
            ['sso_id' => $ssoPayload['sub']],
            ['name' => $ssoPayload['name'], 'email' => $ssoPayload['email']],
        );

        $user->syncRoles($ssoPayload['roles'] ?? []);

        return $user;
    }
}
```

### Events

| Event | When |
|-------|------|
| `UserSynchronizedEvent` | After the synchronizer returns, before login (`$user`, `$ssoPayload`) |
| `SsoLoginFailedEvent` | Any callback failure (`$exception`); the browser only gets a generic 401 |
| `SsoRemoteLogoutReceivedEvent` | A new, valid Single Logout webhook (`$sub`: the server user id) |

Failures are subclasses of `SsoClientException`: `InvalidStateException`, `InvalidSignatureException`, `TokenExpiredException`, `SsoClientMismatchException` (wrong `iss`/`aud`, or `invalid_client`), `TokenReplayedException`, `SsoServerUnreachableException`.

## How it works

1. **Authorize.** `/sso/redirect` stores a random `state` (40 chars) and `code_verifier` (64 chars) in the session and redirects to `{server}/sso/authorize` with `code_challenge = base64url(sha256(verifier))` and `code_challenge_method=S256`.
2. **Callback.** The `state` is pulled from the session (single use) and compared with `hash_equals`. The code is exchanged right away (it lives 60 s and is burned on any attempt) with a form `POST {server}/sso/token` carrying `client_id`, `client_secret`, `code`, `redirect_uri` and `code_verifier`. Only network failures are retried (3 attempts, 100 ms apart); `invalid_request`/`invalid_grant`/`invalid_client` fail immediately.
3. **Verification.**
   - `jwks`: the `access_token` is verified locally against `{server}/.well-known/jwks.json` (cached for `jwks_cache_ttl`, refetched once on an unknown `kid`, so key rotation just works). Only `RS256` is accepted; `iss`, `aud`, `exp`, `nbf` (with `leeway`) are checked and each `jti` is accepted once.
   - `userinfo`: `GET {server}/sso/userinfo` with the Bearer token. The response must carry a valid `X-SSO-Signature` over the raw body and a fresh `X-SSO-Timestamp`. Costs a round-trip, but the server rejects users who already logged out.
4. **Login.** The synchronizer returns the local user, which is logged into the configured guard; the session is regenerated and remembers the server `sub`.
5. **Single Logout.** When the user logs out on the server, it POSTs `{"event":"logout","sub","aud","iat","jti"}` to the webhook. The client checks `X-SSO-Signature = HMAC-SHA256("{X-SSO-Timestamp}.{raw body}", client_secret)` and a timestamp within `signature_tolerance` (300 s), then `event` and `aud`, and answers `204`. A replayed `jti` is acknowledged but ignored, so the server stops retrying. Every local session of that `sub` started before the webhook is ended by `sso.auth` on its next request.

### Production notes

- Use a shared, atomic cache store (Redis, Memcached, database): the `jti` anti-replay markers and the Single Logout markers live there, and every app server must see them.
- Revocation is enforced by `sso.auth`: routes without it do not see a remote logout.
- In `jwks` mode a token stays valid until it expires; logout reaches the client only through the webhook. Use `userinfo` if you need the server to confirm every login.
- The server has no logout endpoint for clients in 1.x: logging out of the client app is local only.

## Testing

```bash
composer test
```

The suite includes interop tests that run the real `laravel-sso-server` (dev dependency) against this client: login in both verification modes and Single Logout.

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Security

If you discover any security related issues, please email the author instead of using the issue tracker.

## Credits

- [Jefferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
