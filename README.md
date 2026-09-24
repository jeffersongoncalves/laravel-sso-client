<div class="filament-hidden">

![Laravel SSO Client](art/jeffersongoncalves-laravel-sso-client.png)

</div>

# Laravel SSO Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-sso-client)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-sso-client/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-sso-client/actions?query=workflow%3ATests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-sso-client/pint.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-sso-client/actions?query=workflow%3Apint+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-sso-client)
[![License](https://img.shields.io/packagist/l/jeffersongoncalves/laravel-sso-client.svg?style=flat-square)](LICENSE.md)

SSO client for Laravel: Authorization Code + PKCE login, RS256/JWKS or HMAC token validation, user sync and back-channel Single Logout. Companion of `jeffersongoncalves/laravel-sso-server`.

## Compatibility

| Package | PHP | Laravel |
|---------|-----|---------|
| 1.x     | 8.2+ | 12.x, 13.x |

## Installation

```bash
composer require jeffersongoncalves/laravel-sso-client
php artisan vendor:publish --tag="laravel-sso-client-config"
```

```dotenv
SSO_SERVER_URL=https://sso.example.com
SSO_CLIENT_ID=billing-app
SSO_CLIENT_SECRET=shared-secret-from-the-server
SSO_VERIFICATION=jwks   # or hmac
```

## Usage

Protect routes with the `sso.auth` middleware. Guests are sent to the SSO Server and come back to the URL they asked for:

```php
Route::middleware(['web', 'sso.auth'])->group(function () {
    Route::get('/dashboard', DashboardController::class);
});
```

Routes registered by the package (prefix configurable via `sso-client.route.prefix`):

| Method | URI | Name | Purpose |
|--------|-----|------|---------|
| GET  | `/sso/redirect`    | `sso-client.redirect`    | Starts the flow (state + PKCE) |
| GET  | `/sso/callback`    | `sso-client.callback`    | Validates, exchanges the code, logs in |
| POST | `/sso/slo-webhook` | `sso-client.slo-webhook` | Back-channel Single Logout |

### Custom user synchronization

The default synchronizer creates or updates an Eloquent user matched on `sso-client.user.identifier`, filling the columns mapped in `sso-client.user.attributes` (new users get a random, unusable password). To keep users in memory only or to map roles, implement the contract and set `sso-client.synchronizer`:

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
| `SsoRemoteLogoutReceivedEvent` | Valid SLO webhook (`$sid`, `$sub`, `$sessionDestroyed`) |

Failures are semantic subclasses of `SsoClientException`: `InvalidStateException`, `InvalidSignatureException`, `TokenExpiredException`, `SsoClientMismatchException`, `TokenReplayedException`, `SsoServerUnreachableException`.

## Protocol (what the Server must implement)

All signatures are the lowercase hex `HMAC-SHA256(raw body, client_secret)` in the `X-SSO-Signature` header.

1. **Authorize** — the client redirects to `GET {server}/sso/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`. The Server redirects back to `redirect_uri?code=...&state=...`.
2. **Token** — the client calls `POST {server}/sso/token` with JSON `{grant_type, code, redirect_uri, client_id, code_verifier}`, signed. Network errors are retried up to 3 times (100 ms apart); HTTP errors are not, since the code is one-time use.
   - `jwks` mode: response `{"token": "<RS256 JWT>"}`, verified against `GET {server}/.well-known/jwks.json` (cached for `jwks_cache_ttl`, refetched once when the `kid` is unknown, so keys can be rotated).
   - `hmac` mode: response body is the claims JSON itself, signed.
3. **Claims** — required: `iss` (= `server_url`), `aud` (contains `client_id`), `sub`, `jti`, `iat`, `exp`. Optional: `sid` (needed for Single Logout) plus any user claims. Each `jti` is accepted once (atomic `Cache::add`) until the token expires.
4. **Single Logout** — the Server calls `POST {client}/sso/slo-webhook` with signed JSON `{"sid", "sub", "iat", "jti"}`. The client rejects `iat` older than `webhook_tolerance` seconds and replayed `jti`, destroys the local session bound to `sid` and answers `204` (also for unknown `sid`s, so the Server stops retrying).

Use an atomic cache store (Redis, Memcached, database) in production: the anti-replay guarantee and the `sid` → session map live in the cache. Server-side logout requires a server-side session driver (`file`, `database`, `redis`...); the `cookie` driver cannot be invalidated remotely.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Security

If you discover any security related issues, please email the author instead of using the issue tracker.

## Credits

- [Jefferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
