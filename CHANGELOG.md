# Changelog

All notable changes to this project will be documented in this file.

## 1.1.0 - 2026-09-24

Support for laravel-sso-server 1.1.

### Added

- **Federated logout:** `POST /sso/logout` (`sso-client.logout`, CSRF-protected) ends the local session, then redirects to the server's `/sso/logout` with the stored access token as `token_hint`. The server ends the SSO session and notifies the user's other apps. Configure the landing page with `SSO_POST_LOGOUT_REDIRECT_URI` (same origin as the redirect URI; defaults to `home`).
- **`email_verified` enforcement:** an existing local account is linked by email only when the server's `email_verified` claim is `true` (and `link_existing_users_by_email` is enabled). Servers that do not send the claim keep the 1.0 behavior. Legacy email-only mode refuses existing users with unverified emails.
- **Laravel Boost:** package guideline and `sso-client-development` skill in `resources/boost`.

### Upgrade notes

- Logout buttons should POST to `route('sso-client.logout')` to get federated logout (requires laravel-sso-server 1.1+). Users who signed in before upgrading have no stored token and are logged out locally only.
- Add `'logout' => '/sso/logout'` to `endpoints` and `post_logout_redirect_uri` if you published the config file before 1.1.0.

Tested on PHP 8.4 + Laravel 13 with SQLite, MySQL and PostgreSQL, including interop tests against laravel-sso-server 1.1.0.

## 1.0.0 - 2026-09-24

First stable release. SSO client for Laravel apps authenticating against jeffersongoncalves/laravel-sso-server 1.x.

### Features

- Authorization Code + PKCE (S256) login with single-use state (sso.auth middleware, redirect and callback routes)
- Token validation locally via RS256/JWKS (cached, key rotation aware, one-time jti) or through the signed /sso/userinfo endpoint
- HMAC-SHA256 signed server messages (X-SSO-Timestamp + X-SSO-Signature, 300s window)
- Back-channel Single Logout webhook: signed, replay-safe, revokes every local session of the server user
- Users linked by the server's immutable sub (publishable sso_id migration); existing local accounts are never taken over by email unless explicitly allowed
- SsoUserSynchronizerContract for custom user mapping; semantic exceptions and events
- Network-only retries; one-time authorization codes are never replayed

### Install

```bash
composer require jeffersongoncalves/laravel-sso-client
php artisan vendor:publish --tag=sso-client-config
php artisan vendor:publish --tag=sso-client-migrations
php artisan migrate


```
Tested on PHP 8.4 + Laravel 13 with SQLite, MySQL and PostgreSQL, including interop tests against the real laravel-sso-server.

## [Unreleased]
