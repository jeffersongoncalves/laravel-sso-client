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
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;
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
        'sso.test/sso/token' => Http::response(['access_token' => $keys->sign($claims), 'token_type' => 'Bearer', 'expires_in' => 3600]),
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
        ->and(strlen($query['state']))->toBeGreaterThanOrEqual(16)
        ->and($verifier)->toMatch('/^[A-Za-z0-9]{43,128}$/')
        ->and($query['code_challenge'])->toHaveLength(43)
        ->toBe(rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='));
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
        ->and(session('sso-client.sub'))->toBe('42')
        ->and(session('sso-client.state'))->toBeNull();

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://sso.test/sso/token'
        && $request->isForm()
        && $request->data() === [
            'grant_type' => 'authorization_code',
            'client_id' => 'client-app',
            'client_secret' => 'shared-secret',
            'code' => 'auth-code',
            'redirect_uri' => route('sso-client.callback'),
            'code_verifier' => $verifier,
        ]);
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
    'expired' => [['exp' => time() - 120, 'iat' => time() - 3720], TokenExpiredException::class],
    'not yet valid' => [['nbf' => time() + 600], InvalidSignatureException::class],
    'other audience' => [['aud' => 'another-app'], SsoClientMismatchException::class],
    'other issuer' => [['iss' => 'https://evil.test'], SsoClientMismatchException::class],
]);

it('rejects a token signed by a key outside the JWKS', function (): void {
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($this->keys->jwks()),
        'sso.test/sso/token' => Http::response(['access_token' => RsaKeyset::generate()->sign(ssoClaims())]),
    ]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    assertLoginFailedWith(InvalidSignatureException::class);
});

it('rejects a token whose header is not RS256', function (): void {
    $header = rtrim(strtr(base64_encode('{"alg":"HS256","typ":"JWT","kid":"key-1"}'), '+/', '-_'), '=');
    $body = rtrim(strtr(base64_encode((string) json_encode(ssoClaims())), '+/', '-_'), '=');
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($this->keys->jwks()),
        'sso.test/sso/token' => Http::response(['access_token' => "{$header}.{$body}.c2ln"]),
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
    fakeServer(RsaKeyset::generate('new-key'), ssoClaims());

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');

    $this->assertAuthenticated();
});

it('maps server token errors to semantic exceptions', function (int $status, string $error, string $exception): void {
    Http::fake(['sso.test/sso/token' => Http::response(['error' => $error, 'error_description' => '...'], $status)]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    assertLoginFailedWith($exception);
    Event::assertDispatched(SsoLoginFailedEvent::class, fn (SsoLoginFailedEvent $e): bool => str_contains($e->exception->getMessage(), $error));
    // The server burns the code on any attempt: never retry a 4xx.
    Http::assertSentCount(1);
})->with([
    'invalid_grant' => [400, 'invalid_grant', SsoClientException::class],
    'invalid_request' => [400, 'invalid_request', SsoClientException::class],
    'invalid_client' => [401, 'invalid_client', SsoClientMismatchException::class],
]);

it('retries network failures and fails with a semantic exception', function (): void {
    Http::fake(['*' => Http::failedConnection()]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    Http::assertSentCount(3);
    assertLoginFailedWith(SsoServerUnreachableException::class);
});

describe('userinfo verification', function (): void {
    beforeEach(fn () => config(['sso-client.verification' => 'userinfo']));

    function fakeUserInfo(string $body, array $headers, int $status = 200): void
    {
        Http::fake([
            'sso.test/sso/token' => Http::response(['access_token' => 'opaque.jwt.value', 'token_type' => 'Bearer', 'expires_in' => 3600]),
            'sso.test/sso/userinfo' => Http::response($body, $status, $headers),
        ]);
    }

    it('logs in with the signed userinfo claims', function (): void {
        $body = (string) json_encode(['name' => 'Ada Lovelace', 'email' => 'ada@example.com', 'sub' => '42']);
        fakeUserInfo($body, ssoSignatureHeaders($body));

        $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');

        $this->assertAuthenticated();
        expect(session('sso-client.sub'))->toBe('42');
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://sso.test/sso/userinfo'
            && $request->hasHeader('Authorization', 'Bearer opaque.jwt.value'));
        Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'jwks'));
    });

    it('rejects unsigned, forged or stale userinfo responses', function (callable $headers, string $exception): void {
        $body = (string) json_encode(['email' => 'ada@example.com', 'sub' => '42']);
        fakeUserInfo($body, $headers($body));

        $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

        $this->assertGuest();
        assertLoginFailedWith($exception);
    })->with([
        'unsigned' => [fn (string $body): array => [], InvalidSignatureException::class],
        'other secret' => [fn (string $body): array => ssoSignatureHeaders($body, secret: 'wrong'), InvalidSignatureException::class],
        'tampered body' => [fn (string $body): array => ssoSignatureHeaders($body.' '), InvalidSignatureException::class],
        'stale timestamp' => [fn (string $body): array => ssoSignatureHeaders($body, time() - 301), TokenExpiredException::class],
    ]);

    it('fails when the server rejects the token', function (): void {
        fakeUserInfo('{"error":"invalid_token"}', ['WWW-Authenticate' => 'Bearer error="invalid_token"'], 401);

        $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

        assertLoginFailedWith(SsoClientException::class);
    });
});
