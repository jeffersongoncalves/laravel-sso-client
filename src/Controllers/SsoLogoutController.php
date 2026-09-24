<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

/**
 * POST /sso/logout — ends the local session, then sends the browser to the
 * server's logout endpoint so the SSO session and the user's other client
 * apps are logged out too. POST + the "web" group keep it CSRF-protected.
 */
class SsoLogoutController
{
    public function __invoke(Request $request, SsoClientManager $sso): RedirectResponse
    {
        $token = $request->session()->get(SsoClientManager::SESSION_ACCESS_TOKEN);

        Auth::guard(config('sso-client.guard'))->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // Not signed in through SSO (or before 1.1): nothing to end on the server.
        if (! is_string($token) || $token === '') {
            return redirect()->to($sso->postLogoutRedirectUri());
        }

        return redirect()->away($sso->logoutUrl($token));
    }
}
