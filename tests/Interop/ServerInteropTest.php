<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SsoClient\Tests\Support\User;
use JeffersonGoncalves\SsoServer\Facades\SsoServer;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;

beforeEach(function (): void {
    Route::get('/dashboard', fn () => 'ok')->middleware(['web', 'sso.auth']);

    $this->serverUser = User::create(['name' => 'Grace Hopper', 'email' => 'grace@example.com', 'password' => 'secret']);
    $this->serverUser->forceFill(['email_verified_at' => now()])->save();
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

it('refuses to link the existing account when the server has not verified the email', function (): void {
    $this->serverUser->forceFill(['email_verified_at' => null])->save();

    $authorizeUrl = (string) $this->get('/sso/redirect')->headers->get('Location');
    $callbackUrl = (string) $this->actingAs($this->serverUser, 'idp')->get($authorizeUrl)->headers->get('Location');

    $this->get($callbackUrl)->assertUnauthorized();

    $this->assertGuest('web');
    expect($this->serverUser->fresh()->sso_id)->toBeNull();
});

it('logs out of the server and every other client from the client app', function (): void {
    signInThroughServer();

    $serverLogoutUrl = (string) $this->post('/sso/logout')->assertRedirect()->headers->get('Location');
    $this->assertGuest('web');

    parse_str((string) parse_url($serverLogoutUrl, PHP_URL_QUERY), $query);

    $this->actingAs($this->serverUser, 'idp')->get($serverLogoutUrl)->assertRedirect($query['post_logout_redirect_uri']);

    expect(SsoActiveSession::count())->toBe(0);
    $this->assertGuest('idp');
    // The initiating client already logged out locally: no webhook for it.
    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), '/sso/slo-webhook'));
});

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
