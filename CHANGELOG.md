# Changelog

All notable changes to this project will be documented in this file.

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
