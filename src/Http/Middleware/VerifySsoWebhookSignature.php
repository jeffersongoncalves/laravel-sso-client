<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;
use JeffersonGoncalves\SsoClient\Exceptions\TokenExpiredException;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Webhook body: {"sid": "...", "sub": "...", "iat": 1700000000, "jti": "..."}
 * Header X-SSO-Signature: hex HMAC-SHA256 of the raw body with the client secret.
 */
class VerifySsoWebhookSignature
{
    public function __construct(
        protected SsoClientManager $sso,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            $this->sso->verifySignature($request->getContent(), $request->header(SsoClientManager::SIGNATURE_HEADER));

            $tolerance = (int) config('sso-client.webhook_tolerance', 60);
            $iat = $request->json('iat');
            $jti = $request->json('jti');

            if (! is_numeric($iat) || abs(time() - (int) $iat) > $tolerance) {
                throw new TokenExpiredException('Webhook "iat" is outside the tolerance window.');
            }

            if (! is_string($jti) || $jti === '') {
                throw new SsoClientException('Webhook is missing "jti".');
            }

            // Covers the whole window where "iat" would still be accepted.
            $this->sso->consumeOnce('webhook:'.$jti, 2 * $tolerance);
        } catch (SsoClientException) {
            abort(401, 'Invalid SSO webhook.');
        }

        return $next($request);
    }
}
