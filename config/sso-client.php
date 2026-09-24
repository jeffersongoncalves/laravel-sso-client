<?php

declare(strict_types=1);

use JeffersonGoncalves\SsoClient\Services\DefaultUserSynchronizer;

return [

    /*
    |--------------------------------------------------------------------------
    | SSO Server
    |--------------------------------------------------------------------------
    |
    | Base URL of the SSO Server. It is also the expected "iss" claim of every
    | token. The client secret is the shared HMAC-SHA256 key used to sign the
    | token request and to verify webhooks (and tokens, in "hmac" mode).
    |
    */

    'server_url' => env('SSO_SERVER_URL'),

    'client_id' => env('SSO_CLIENT_ID'),

    'client_secret' => env('SSO_CLIENT_SECRET'),

    // Defaults to the package's own callback route when null.
    'redirect_uri' => env('SSO_REDIRECT_URI'),

    'endpoints' => [
        'authorize' => '/sso/authorize',
        'token' => '/sso/token',
        'jwks' => '/.well-known/jwks.json',
    ],

    /*
    |--------------------------------------------------------------------------
    | Token verification
    |--------------------------------------------------------------------------
    |
    | "jwks": the token endpoint returns {"token": "<RS256 JWT>"}, verified
    |         against the server's JWKS (cached, refetched on unknown "kid").
    | "hmac": the token endpoint returns the claims as JSON, signed with
    |         HMAC-SHA256 of the raw body in the X-SSO-Signature header.
    |
    */

    'verification' => env('SSO_VERIFICATION', 'jwks'),

    'jwks_cache_ttl' => 3600,

    // Clock skew tolerated when checking "exp"/"iat", in seconds.
    'leeway' => 30,

    // Max age of a Single Logout webhook ("iat" claim), in seconds.
    'webhook_tolerance' => 60,

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
