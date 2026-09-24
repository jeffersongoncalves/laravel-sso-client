<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "sso.auth[:guard]": ends sessions revoked by Single Logout
 * and sends guests through the SSO flow, back to the URL they asked for.
 */
class EnsureSsoAuthenticated
{
    public function __construct(
        protected SsoClientManager $sso,
    ) {}

    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $auth = Auth::guard($guard ?? config('sso-client.guard'));

        if ($auth->check() && $request->hasSession() && $this->sso->isRevoked($request->session())) {
            $auth->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        if ($auth->guest()) {
            if ($request->expectsJson()) {
                abort(401);
            }

            return redirect()->guest(route('sso-client.redirect'));
        }

        return $next($request);
    }
}
