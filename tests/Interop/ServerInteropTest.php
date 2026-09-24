<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SsoClient\Tests\Support\User;
use JeffersonGoncalves\SsoServer\Facades\SsoServer;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;

beforeEach(function (): void {
    Route::get('/dashboard', fn () => 'ok')->middleware(['web', 'sso.auth']);

    $this->serverUser = User::create(['name' => 'Grace Hopper', 'email' => 'grace@example.com', 'password' => 'secret']);
});

/**
 * Browser round-trip: client redirect -> server authorize (logged in on the
 * "idp" guard) -> client callback.
 */
function signInThroughServer(): void
{
    $test = test();
    $authorizeUrl = (string) $test->get('/dashboard')->assertRedirect()->headers->get('Location');
    $authorizeUrl = (string) $test->get($authorizeUrl)->headers->get('Location');

    expect($authorizeUrl)->toStartWith('https://idp.test/sso/authorize?');

    $callbackUrl = (string) $test->actingAs($test->serverUser, 'idp')->get($authorizeUrl)->assertRedirect()->headers->get('Location');

    expect(parse_url($callbackUrl, PHP_URL_PATH))->toBe('/sso/callback')
        ->and($callbackUrl)->toContain('?code=');

    $test->get($callbackUrl)->assertRedirect('/dashboard');
}

it('signs in against the real server with JWKS verification', function (): void {
    signInThroughServer();

    $this->assertAuthenticatedAs($this->serverUser->fresh(), 'web');
    $this->get('/dashboard')->assertOk();
    expect(session('sso-client.sub'))->toBe((string) $this->serverUser->id)
        ->and(SsoActiveSession::where('user_id', (string) $this->serverUser->id)->count())->toBe(1);
});

it('signs in against the real server with userinfo verification', function (): void {
    config(['sso-client.verification' => 'userinfo']);

    signInThroughServer();

    $this->assertAuthenticatedAs($this->serverUser->fresh(), 'web');
});

it('ends the client session when the server logs the user out', function (): void {
    signInThroughServer();
    $this->get('/dashboard')->assertOk();

    // Same path as a Logout event on the server's guard: queues the signed webhook.
    SsoServer::logoutUser((string) $this->serverUser->id);

    $this->get('/dashboard')->assertRedirect(route('sso-client.redirect'));
    $this->assertGuest('web');
});
