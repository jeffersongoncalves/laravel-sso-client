<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SsoClient\Controllers\SsoCallbackController;
use JeffersonGoncalves\SsoClient\Controllers\SsoLogoutController;
use JeffersonGoncalves\SsoClient\Controllers\SsoLogoutWebhookController;
use JeffersonGoncalves\SsoClient\Controllers\SsoRedirectController;
use JeffersonGoncalves\SsoClient\Http\Middleware\VerifySsoWebhookSignature;

Route::prefix((string) config('sso-client.route.prefix', 'sso'))
    ->name('sso-client.')
    ->group(function (): void {
        Route::middleware((array) config('sso-client.route.middleware', ['web']))->group(function (): void {
            Route::get('redirect', SsoRedirectController::class)->name('redirect');
            Route::get('callback', SsoCallbackController::class)->name('callback');
            Route::post('logout', SsoLogoutController::class)->name('logout');
        });

        // Server-to-server: no session, no CSRF; authenticated by HMAC signature.
        Route::post('slo-webhook', SsoLogoutWebhookController::class)
            ->middleware(VerifySsoWebhookSignature::class)
            ->name('slo-webhook');
    });
