<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

/**
 * @method static string authorizationUrl(\Illuminate\Contracts\Session\Session $session)
 * @method static \Illuminate\Contracts\Auth\Authenticatable handleCallback(\Illuminate\Http\Request $request)
 * @method static array<string, mixed> exchangeCode(string $code, string $codeVerifier)
 * @method static void verifySignature(string $payload, ?string $signature)
 * @method static string sign(string $payload)
 * @method static bool logoutSession(string $sid)
 *
 * @see SsoClientManager
 */
class SsoClient extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SsoClientManager::class;
    }
}
