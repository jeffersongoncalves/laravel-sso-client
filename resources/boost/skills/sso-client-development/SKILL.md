---
name: sso-client-development
description: Install, configure, extend and troubleshoot jeffersongoncalves/laravel-sso-client (SSO login against laravel-sso-server, user sync, Single Logout, Filament panels).
---

# SSO Client Development

## When to use this skill

Use this skill when:
- Adding SSO login to this app with `jeffersongoncalves/laravel-sso-client`
- Mapping extra server claims (roles, avatar, tenant) to local users
- Protecting a Filament panel with SSO
- Debugging failed SSO logins or Single Logout

## Setup checklist

1. On the **server** app, register the client (prints `client_id` and `client_secret`):

```bash
php artisan sso-server:client "My App" https://my-app.test/sso/callback --slo=https://my-app.test/sso/slo-webhook
```

2. On this app:

```bash
composer require jeffersongoncalves/laravel-sso-client
php artisan vendor:publish --tag=sso-client-config
php artisan vendor:publish --tag=sso-client-migrations
php artisan migrate
```

3. Set `SSO_SERVER_URL`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET` in `.env` (plus `SSO_ISSUER` if the server's `sso-server.issuer` is not its URL).
4. Put `sso.auth` on the routes that require SSO. Nothing else to register: routes, alias and the CSRF-free webhook come from the service provider.
5. Make the logout button POST to the package route (federated logout needs laravel-sso-server 1.1+):

```blade
<form method="POST" action="{{ route('sso-client.logout') }}">
    @csrf
    <button type="submit">Log out</button>
</form>
```

## Custom user synchronization

The default `DefaultUserSynchronizer` links by `sso_id` = `sub`, creates new users and refuses to take over unlinked accounts by email. To map extra claims, implement the contract and point `sso-client.synchronizer` at it:

```php
namespace App\Sso;

use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;

class RoleAwareSynchronizer implements SsoUserSynchronizerContract
{
    public function synchronize(array $ssoPayload): Authenticatable
    {
        // Link by the immutable sub, never by email.
        $user = User::updateOrCreate(
            ['sso_id' => $ssoPayload['sub']],
            ['name' => $ssoPayload['name'] ?? 'SSO user', 'email' => $ssoPayload['email']],
        );

        $user->syncRoles($ssoPayload['roles'] ?? []);

        return $user;
    }
}
```

```php
// config/sso-client.php
'synchronizer' => \App\Sso\RoleAwareSynchronizer::class,
```

Extra claims only exist if the server's `sso-server.serializer` sends them (default: `name`, `email`). A custom synchronizer replaces the built-in account-takeover guard: throw `JeffersonGoncalves\SsoClient\Exceptions\AccountLinkingException` yourself if an unlinked local user already owns the email, and never link by email unless `$ssoPayload['email_verified'] === true`.

## Filament panels

Run SSO before Filament's own `Authenticate`, so guests go to the SSO server and `canAccessPanel()` is still enforced:

```php
use Filament\Http\Middleware\Authenticate;
use JeffersonGoncalves\SsoClient\Http\Middleware\EnsureSsoAuthenticated;

$panel->authMiddleware([
    EnsureSsoAuthenticated::class,
    Authenticate::class,
]);
```

For a federated logout from the panel, point Filament's logout at the package route (e.g. a user menu item or a custom `LogoutResponse`) instead of Filament's local-only logout.

Never replace `Authenticate` with `EnsureSsoAuthenticated` alone: every SSO user would get into the panel.

## Verification

- A guest request to a protected route returns 302 to `/sso/redirect`, which redirects to `{SSO_SERVER_URL}/sso/authorize` with `state`, `code_challenge` and `code_challenge_method=S256`.
- A signed webhook needs both headers, with the signature over `"{timestamp}.{raw body}"`:

```php
$body = json_encode(['event' => 'logout', 'sub' => '42', 'aud' => config('sso-client.client_id'), 'iat' => time(), 'jti' => (string) Str::uuid()]);
$timestamp = (string) time();

$this->call('POST', '/sso/slo-webhook', server: [
    'CONTENT_TYPE' => 'application/json',
    'HTTP_X_SSO_TIMESTAMP' => $timestamp,
    'HTTP_X_SSO_SIGNATURE' => hash_hmac('sha256', $timestamp.'.'.$body, config('sso-client.client_secret')),
], content: $body)->assertNoContent();
```

## Troubleshooting

Callback failures always answer a generic 401; listen to `SsoLoginFailedEvent` (`$event->exception`) to see why.

| Exception | Usual cause |
|-----------|-------------|
| `InvalidStateException` | Session lost between redirect and callback (cookie domain, session driver), or a replayed callback URL |
| `SsoClientMismatchException` | Wrong `SSO_CLIENT_ID`/`SSO_CLIENT_SECRET` (`invalid_client`), or `iss` differs: set `SSO_ISSUER` to the server's `APP_URL` |
| `SsoClientException` mentioning `invalid_grant` | Code expired (60 s) or already used, or the redirect URI differs from the registered one |
| `InvalidSignatureException` | JWKS/key mismatch, or a secret mismatch in `userinfo` mode |
| `TokenExpiredException` | Clock skew between servers beyond `sso-client.leeway` / `signature_tolerance` |
| `AccountLinkingException` | An unlinked local user already has that email (or the server reports `email_verified: false`): link it deliberately (set its `sso_id`) |
| `SsoServerUnreachableException` | Network/DNS/TLS failure after 3 attempts |

Webhook answers 401 = bad signature or timestamp older than 300 s; 422 = payload not a `logout` for this `client_id`. A replayed `jti` gets 204 and is ignored.
