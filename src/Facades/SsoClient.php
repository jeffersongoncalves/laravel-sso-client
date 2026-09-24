<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

/**
 * @method static string authorizationUrl(\Illuminate\Contracts\Session\Session $session)
 * @method static \Illuminate\Contracts\Auth\Authenticatable handleCallback(\Illuminate\Http\Request $request)
 * @method static array<string, mixed> exchangeCode(string $code, string $codeVerifier)
 * @method static array<string, mixed> verifyAccessToken(string $token)
 * @method static array<string, mixed> fetchUserInfo(string $token)
 * @method static void verifySignature(string $payload, ?string $timestamp, ?string $signature)
 * @method static string logoutUrl(string $accessToken)
 * @method static string postLogoutRedirectUri()
 * @method static void logoutSubject(string $sub)
 * @method static bool isRevoked(\Illuminate\Contracts\Session\Session $session)
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
