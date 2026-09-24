## Laravel SSO Client

`jeffersongoncalves/laravel-sso-client` signs users of this Laravel app in through a central `jeffersongoncalves/laravel-sso-server` (Authorization Code + PKCE S256), keeps local users in sync and ends local sessions on back-channel Single Logout.

### Features

- **Routes (auto-registered):** `GET /sso/redirect` (`sso-client.redirect`), `GET /sso/callback` (`sso-client.callback`), `POST /sso/logout` (`sso-client.logout`), `POST /sso/slo-webhook` (`sso-client.slo-webhook`). The prefix comes from `sso-client.route.prefix`.
- **Logout:** logout buttons must POST (with `@csrf`) to `route('sso-client.logout')`, never call `Auth::logout()` alone: the package ends the local session, then redirects to the server (1.1+) to end the SSO session and the user's other apps.
- **`sso.auth` middleware (auto-registered alias):** sends guests through the SSO flow and ends sessions revoked by Single Logout. Protect SSO routes with it:

@verbatim
<code-snippet name="Protect routes with SSO" lang="php">
Route::middleware(['web', 'sso.auth'])->group(function () {
    Route::get('/dashboard', DashboardController::class)->name('dashboard');
});
</code-snippet>
@endverbatim

- **Token verification:** `SSO_VERIFICATION=jwks` (default, local RS256 against the server JWKS) or `userinfo` (signed server call on every login; sees server-side logout).
- **User linking:** local users are linked by `users.sso_id` = the server `sub`. A login whose email belongs to an existing, unlinked local account fails with `AccountLinkingException` (HTTP 401); linking by email additionally requires the server's `email_verified` claim to be `true`.
- **Events:** `UserSynchronizedEvent`, `SsoLoginFailedEvent` (the only place failure details go), `SsoRemoteLogoutReceivedEvent`.

### Configuration

@verbatim
<code-snippet name="Install" lang="bash">
composer require jeffersongoncalves/laravel-sso-client
php artisan vendor:publish --tag=sso-client-config
php artisan vendor:publish --tag=sso-client-migrations
php artisan migrate
</code-snippet>
@endverbatim

@verbatim
<code-snippet name=".env" lang="env">
SSO_SERVER_URL=https://sso.example.com
SSO_CLIENT_ID=<client_id from `php artisan sso-server:client`>
SSO_CLIENT_SECRET=<client_secret from `php artisan sso-server:client`>
# Optional: the server's sso-server.issuer when it differs from SSO_SERVER_URL
SSO_ISSUER=
SSO_VERIFICATION=jwks
</code-snippet>
@endverbatim

The redirect URI defaults to the `sso-client.callback` route and must match the one registered on the server exactly; register the Single Logout URL as `{APP_URL}/sso/slo-webhook`.

### Best Practices

- The publish tags are `sso-client-config` and `sso-client-migrations` (no `laravel-` prefix).
- Do not register the `sso.auth` alias yourself and do not add a CSRF exception for the webhook: the provider registers the alias, and the webhook route is outside the `web` group on purpose (it is authenticated by an HMAC signature). Never move it into `web` or behind `auth`.
- Keep `sso-client.user.link_existing_users_by_email` set to `false` and `sso_id_column` set to `sso_id` unless the user explicitly asks otherwise; both relax the account-takeover protection.
- Use a shared, atomic cache store (Redis, Memcached, database) in production: replay protection and Single Logout markers live in the cache.
- Remote logout is only enforced on routes that use `sso.auth`.
- Let `SsoCallbackController` log users in; never trust `sub`, `email` or any claim coming from the browser.
- `SSO_CLIENT_SECRET` stays server-side only.
