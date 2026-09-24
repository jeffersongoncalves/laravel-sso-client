<?php

namespace JeffersonGoncalves\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \JeffersonGoncalves\SsoClient\SsoClient
 */
class SsoClient extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-sso-client';
    }
}
