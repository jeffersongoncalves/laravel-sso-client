<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use JeffersonGoncalves\SsoClient\Events\SsoRemoteLogoutReceivedEvent;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

/**
 * Back-channel Single Logout. Signature, freshness and replay are already
 * checked by VerifySsoWebhookSignature.
 */
class SsoLogoutWebhookController
{
    public function __invoke(Request $request, SsoClientManager $sso): Response
    {
        $sid = $request->json('sid');
        $sub = $request->json('sub');

        if (! is_string($sid) || $sid === '') {
            abort(422, 'Missing "sid".');
        }

        $destroyed = $sso->logoutSession($sid);

        SsoRemoteLogoutReceivedEvent::dispatch($sid, is_string($sub) ? $sub : null, $destroyed);

        // 204 even when no local session exists: the Server must not retry forever.
        return response()->noContent();
    }
}
