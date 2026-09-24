<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "sso.auth[:guard]": guests are sent through the SSO flow
 * and come back to the URL they asked for.
 */
class EnsureSsoAuthenticated
{
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        if (Auth::guard($guard ?? config('sso-client.guard'))->guest()) {
            if ($request->expectsJson()) {
                abort(401);
            }

            return redirect()->guest(route('sso-client.redirect'));
        }

        return $next($request);
    }
}
