<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use JeffersonGoncalves\SsoClient\Events\SsoRemoteLogoutReceivedEvent;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

/**
 * Back-channel Single Logout. The signature and timestamp are already checked
 * by VerifySsoWebhookSignature.
 *
 * Body: {"event": "logout", "sub": "42", "aud": "<client_id>", "iat": 1790000000, "jti": "<uuid>"}
 */
class SsoLogoutWebhookController
{
    public function __invoke(Request $request, SsoClientManager $sso): Response
    {
        $sub = $request->json('sub');
        $jti = $request->json('jti');

        if ($request->json('event') !== 'logout'
            || $request->json('aud') !== $sso->clientId()
            || ! is_string($sub) || $sub === ''
            || ! is_string($jti) || $jti === '') {
            abort(422, 'Invalid SSO logout payload.');
        }

        // A replay is acknowledged but ignored: a non-2xx would make the server retry it.
        if ($sso->consumeOnce('webhook:'.$jti, 2 * $sso->signatureTolerance())) {
            $sso->logoutSubject($sub);

            SsoRemoteLogoutReceivedEvent::dispatch($sub);
        }

        return response()->noContent();
    }
}
