<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use JeffersonGoncalves\SsoClient\Events\SsoLoginFailedEvent;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

class SsoCallbackController
{
    public function __invoke(Request $request, SsoClientManager $sso): RedirectResponse
    {
        try {
            $sso->handleCallback($request);
        } catch (SsoClientException $e) {
            SsoLoginFailedEvent::dispatch($e);

            // Details go to the event/log, never to the browser.
            abort(401, 'SSO authentication failed.');
        }

        return redirect()->intended((string) config('sso-client.home', '/'));
    }
}
