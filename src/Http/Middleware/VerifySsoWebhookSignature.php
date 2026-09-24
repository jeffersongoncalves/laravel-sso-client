<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates server-to-server calls: X-SSO-Signature must be the hex
 * HMAC-SHA256 of "{X-SSO-Timestamp}.{raw body}" with the client secret, and
 * the timestamp must be within sso-client.signature_tolerance.
 */
class VerifySsoWebhookSignature
{
    public function __construct(
        protected SsoClientManager $sso,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            $this->sso->verifySignature(
                $request->getContent(),
                $request->header(SsoClientManager::TIMESTAMP_HEADER),
                $request->header(SsoClientManager::SIGNATURE_HEADER),
            );
        } catch (SsoClientException) {
            abort(401, 'Invalid SSO signature.');
        }

        return $next($request);
    }
}
