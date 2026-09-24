<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SsoClient\Events\SsoLoginFailedEvent;
use JeffersonGoncalves\SsoClient\Events\UserSynchronizedEvent;
use JeffersonGoncalves\SsoClient\Exceptions\InvalidSignatureException;
use JeffersonGoncalves\SsoClient\Exceptions\InvalidStateException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientMismatchException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoServerUnreachableException;
use JeffersonGoncalves\SsoClient\Exceptions\TokenExpiredException;
use JeffersonGoncalves\SsoClient\Exceptions\TokenReplayedException;
use JeffersonGoncalves\SsoClient\Tests\Support\RsaKeyset;
use JeffersonGoncalves\SsoClient\Tests\Support\User;

beforeEach(function (): void {
    $this->keys = RsaKeyset::generate();
    Event::fake([SsoLoginFailedEvent::class, UserSynchronizedEvent::class]);
});

function fakeServer(RsaKeyset $keys, array $claims): void
{
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($keys->jwks()),
        'sso.test/sso/token' => Http::response(['token' => $keys->sign($claims)]),
    ]);
}

function assertLoginFailedWith(string $exception): void
{
    Event::assertDispatched(SsoLoginFailedEvent::class, fn (SsoLoginFailedEvent $e): bool => $e->exception instanceof $exception);
}

it('redirects to the server with state and an S256 PKCE challenge', function (): void {
    $location = (string) $this->get('/sso/redirect')->assertRedirect()->headers->get('Location');

    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
    $verifier = session('sso-client.code_verifier');

    expect($location)->toStartWith('https://sso.test/sso/authorize?')
        ->and($query)->toMatchArray([
            'response_type' => 'code',
            'client_id' => 'client-app',
            'redirect_uri' => route('sso-client.callback'),
            'state' => session('sso-client.state'),
            'code_challenge_method' => 'S256',
        ])
        ->and($query['code_challenge'])->toBe(rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='));
});

it('completes the handshake, creates the local user and logs in', function (): void {
    Route::get('/dashboard', fn () => 'ok')->middleware(['web', 'sso.auth']);
    fakeServer($this->keys, ssoClaims());

    $this->get('/dashboard')->assertRedirect(route('sso-client.redirect'));
    $state = beginSsoLogin();
    $verifier = session('sso-client.code_verifier');

    $this->get("/sso/callback?code=auth-code&state={$state}")->assertRedirect('/dashboard');

    $this->assertAuthenticated();
    expect(User::sole())->email->toBe('ada@example.com')->name->toBe('Ada Lovelace')
        ->and(session('sso-client.state'))->toBeNull();

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://sso.test/sso/token'
        && $request['code'] === 'auth-code'
        && $request['code_verifier'] === $verifier
        && hash_equals(hash_hmac('sha256', $request->body(), 'shared-secret'), $request->header('X-SSO-Signature')[0]));
    Event::assertDispatched(UserSynchronizedEvent::class);
    $this->get('/dashboard')->assertOk();
});

it('updates an existing user instead of duplicating it', function (): void {
    User::create(['name' => 'Old Name', 'email' => 'ada@example.com', 'password' => 'secret']);
    fakeServer($this->keys, ssoClaims());

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');

    expect(User::count())->toBe(1)->and(User::sole()->name)->toBe('Ada Lovelace');
});

it('rejects a callback whose state does not match the session', function (): void {
    fakeServer($this->keys, ssoClaims());
    beginSsoLogin();

    $this->get('/sso/callback?code=c&state=forged')->assertUnauthorized();

    $this->assertGuest();
    Http::assertNothingSent();
    assertLoginFailedWith(InvalidStateException::class);
});

it('rejects tokens that fail validation', function (array $claims, string $exception): void {
    fakeServer($this->keys, ssoClaims($claims));

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    $this->assertGuest();
    assertLoginFailedWith($exception);
})->with([
    'expired' => [['exp' => time() - 120, 'iat' => time() - 180], TokenExpiredException::class],
    'other audience' => [['aud' => 'another-app'], SsoClientMismatchException::class],
    'other issuer' => [['iss' => 'https://evil.test'], SsoClientMismatchException::class],
]);

it('rejects a token signed by a key outside the JWKS', function (): void {
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($this->keys->jwks()),
        'sso.test/sso/token' => Http::response(['token' => RsaKeyset::generate()->sign(ssoClaims())]),
    ]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    assertLoginFailedWith(InvalidSignatureException::class);
});

it('accepts a token once and rejects its replay', function (): void {
    fakeServer($this->keys, ssoClaims(['jti' => 'same-jti']));

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');
    auth()->logout();
    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    assertLoginFailedWith(TokenReplayedException::class);
});

it('refetches the JWKS when the server rotates its key', function (): void {
    cache()->put('sso-client:jwks', RsaKeyset::generate('old-key')->jwks());
    $rotated = RsaKeyset::generate('new-key');
    fakeServer($rotated, ssoClaims());

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');

    $this->assertAuthenticated();
});

it('verifies HMAC-signed token responses in hmac mode', function (string $signature, bool $accepted): void {
    config(['sso-client.verification' => 'hmac']);
    $body = json_encode(ssoClaims());
    $signature = $signature === 'valid' ? hash_hmac('sha256', $body, 'shared-secret') : $signature;
    Http::fake(['sso.test/sso/token' => Http::response($body, 200, ['X-SSO-Signature' => $signature])]);

    $response = $this->get('/sso/callback?code=c&state='.beginSsoLogin());

    if ($accepted) {
        $response->assertRedirect('/');
        $this->assertAuthenticated();
    } else {
        $response->assertUnauthorized();
        assertLoginFailedWith(InvalidSignatureException::class);
    }
})->with([
    'valid signature' => ['valid', true],
    'forged signature' => [str_repeat('0', 64), false],
]);

it('retries network failures and fails with a semantic exception', function (): void {
    Http::fake(['*' => Http::failedConnection()]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    Http::assertSentCount(3);
    assertLoginFailedWith(SsoServerUnreachableException::class);
});

it('does not retry a rejected authorization code', function (): void {
    Http::fake(['sso.test/sso/token' => Http::response(['error' => 'invalid_grant'], 400)]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    Http::assertSentCount(1);
});
