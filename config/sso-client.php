<?php

declare(strict_types=1);

use JeffersonGoncalves\SsoClient\Services\DefaultUserSynchronizer;

return [

    /*
    |--------------------------------------------------------------------------
    | SSO Server
    |--------------------------------------------------------------------------
    |
    | Credentials come from `php artisan sso-server:client` on the server. The
    | client secret authenticates the token exchange and is the HMAC-SHA256
    | key of signed server responses (userinfo, Single Logout webhook).
    |
    */

    'server_url' => env('SSO_SERVER_URL'),

    // Expected "iss" claim: the server's sso-server.issuer (its APP_URL by
    // default). Null uses server_url.
    'issuer' => env('SSO_ISSUER'),

    'client_id' => env('SSO_CLIENT_ID'),

    'client_secret' => env('SSO_CLIENT_SECRET'),

    // Must match the redirect_uri registered on the server exactly.
    // Null uses this package's callback route.
    'redirect_uri' => env('SSO_REDIRECT_URI'),

    // Paths on the server (they follow its sso-server.routes.prefix).
    'endpoints' => [
        'authorize' => '/sso/authorize',
        'token' => '/sso/token',
        'userinfo' => '/sso/userinfo',
        'jwks' => '/.well-known/jwks.json',
        // Client-initiated logout (laravel-sso-server 1.1+).
        'logout' => '/sso/logout',
    ],

    // Where the server sends the browser after POST /sso/logout. Must have the
    // same origin as redirect_uri. Null uses the "home" URL below.
    'post_logout_redirect_uri' => env('SSO_POST_LOGOUT_REDIRECT_URI'),

    /*
    |--------------------------------------------------------------------------
    | Token verification
    |--------------------------------------------------------------------------
    |
    | "jwks":     verify the RS256 access token locally against the server's
    |             JWKS (cached, refetched once on an unknown "kid").
    | "userinfo": ask the server (GET /sso/userinfo) and verify its signed
    |             response. One extra round-trip, but sees server-side logout.
    |
    */

    'verification' => env('SSO_VERIFICATION', 'jwks'),

    'jwks_cache_ttl' => 300,

    // Clock skew tolerated on exp/nbf/iat, in seconds.
    'leeway' => 30,

    // Max age of X-SSO-Timestamp on signed server messages, in seconds.
    'signature_tolerance' => 300,

    'http_timeout' => 5,

    /*
    |--------------------------------------------------------------------------
    | Local authentication
    |--------------------------------------------------------------------------
    */

    // Null uses the application's default guard.
    'guard' => null,

    'home' => '/',

    'synchronizer' => DefaultUserSynchronizer::class,

    'user' => [
        // Null uses auth.providers.users.model.
        'model' => null,

        // Column that stores the server's immutable "sub" and links local users
        // to it (publish the migration: --tag="sso-client-migrations").
        // Null matches users by email only: insecure unless the server verifies
        // every email and never lets users change it.
        'sso_id_column' => 'sso_id',

        // Local email column, used to detect accounts that already exist.
        'email_column' => 'email',

        // An SSO login whose email belongs to an existing local account that
        // was never linked is rejected (account takeover guard). When enabled,
        // the account is linked only if the "email_verified" claim is true
        // (laravel-sso-server 1.1+); servers that omit the claim are trusted
        // to verify every email.
        'link_existing_users_by_email' => false,

        // Local column => claim (dot notation) in the SSO payload.
        'attributes' => [
            'name' => 'name',
            'email' => 'email',
        ],
    ],

    'route' => [
        'prefix' => 'sso',
        'middleware' => ['web'],
    ],

];
