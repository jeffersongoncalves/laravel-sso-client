<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use JeffersonGoncalves\SsoClient\Tests\InteropTestCase;
use JeffersonGoncalves\SsoClient\Tests\TestCase;

uses(TestCase::class)->in('Feature');
uses(InteropTestCase::class)->in('Interop');

/**
 * Access token claims as laravel-sso-server 1.0 issues them for "client-app".
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function ssoClaims(array $overrides = []): array
{
    return array_merge([
        'name' => 'Ada Lovelace',
        'email' => 'ada@example.com',
        'iss' => 'https://sso.test',
        'sub' => '42',
        'aud' => 'client-app',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + 3600,
        'jti' => (string) Str::uuid(),
    ], $overrides);
}

/**
 * The server's signatureHeaders(): HMAC-SHA256 of "{timestamp}.{body}".
 *
 * @return array{X-SSO-Timestamp: string, X-SSO-Signature: string}
 */
function ssoSignatureHeaders(string $body, ?int $timestamp = null, string $secret = 'shared-secret'): array
{
    $timestamp = (string) ($timestamp ?? time());

    return [
        'X-SSO-Timestamp' => $timestamp,
        'X-SSO-Signature' => hash_hmac('sha256', $timestamp.'.'.$body, $secret),
    ];
}

/**
 * Hit the redirect route and return the "state" sent to the Server.
 */
function beginSsoLogin(): string
{
    $location = (string) test()->get('/sso/redirect')->headers->get('Location');

    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    return (string) $query['state'];
}
