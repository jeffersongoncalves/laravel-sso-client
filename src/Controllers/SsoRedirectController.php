<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;

class SsoRedirectController
{
    public function __invoke(Request $request, SsoClientManager $sso): RedirectResponse
    {
        return redirect()->away($sso->authorizationUrl($request->session()));
    }
}
