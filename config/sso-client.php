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
    ],

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

        // Column used to find the local user; its value comes from "attributes".
        // To link by the server id instead, add an "sso_id" column, map
        // 'sso_id' => 'sub' below and set this to 'sso_id'.
        'identifier' => 'email',

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
