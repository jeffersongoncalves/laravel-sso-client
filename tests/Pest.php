<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use JeffersonGoncalves\SsoClient\Tests\TestCase;

uses(TestCase::class)->in('Feature');

/**
 * Claims the SSO Server would issue for "client-app".
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function ssoClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://sso.test',
        'aud' => 'client-app',
        'sub' => 'user-42',
        'sid' => 'server-session-1',
        'jti' => (string) Str::uuid(),
        'iat' => time(),
        'exp' => time() + 60,
        'name' => 'Ada Lovelace',
        'email' => 'ada@example.com',
    ], $overrides);
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
