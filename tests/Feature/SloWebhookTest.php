<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use JeffersonGoncalves\SsoClient\Events\SsoRemoteLogoutReceivedEvent;
use JeffersonGoncalves\SsoClient\Tests\Support\RsaKeyset;

/**
 * POST the webhook exactly as DispatchSingleLogoutJob does.
 *
 * @param  array<string, mixed>  $overrides
 * @param  array<string, string>|null  $headers
 */
function sendSloWebhook(array $overrides = [], ?array $headers = null): TestResponse
{
    $body = (string) json_encode(array_merge([
        'event' => 'logout',
        'sub' => '42',
        'aud' => 'client-app',
        'iat' => time(),
        'jti' => (string) Str::uuid(),
    ], $overrides));

    $server = ['CONTENT_TYPE' => 'application/json'];

    foreach ($headers ?? ssoSignatureHeaders($body) as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    return test()->call('POST', '/sso/slo-webhook', server: $server, content: $body);
}

function loginThroughSso(): void
{
    test()->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect();
}

beforeEach(function (): void {
    Event::fake([SsoRemoteLogoutReceivedEvent::class]);
    Route::get('/dashboard', fn () => 'ok')->middleware(['web', 'sso.auth']);

    // Fresh token (new jti) on every exchange, like the real server.
    $keys = RsaKeyset::generate();
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($keys->jwks()),
        'sso.test/sso/token' => fn () => Http::response(['access_token' => $keys->sign(ssoClaims())]),
    ]);

    loginThroughSso();
    $this->get('/dashboard')->assertOk();
});

it('revokes the local session of the logged-out server user', function (): void {
    sendSloWebhook()->assertNoContent();

    $this->get('/dashboard')->assertRedirect(route('sso-client.redirect'));
    $this->assertGuest();
    Event::assertDispatched(SsoRemoteLogoutReceivedEvent::class, fn ($e): bool => $e->sub === '42');
});

it('does not touch sessions of other server users', function (): void {
    sendSloWebhook(['sub' => '7'])->assertNoContent();

    $this->get('/dashboard')->assertOk();
});

it('lets the user sign in again after a remote logout', function (): void {
    sendSloWebhook()->assertNoContent();
    $this->get('/dashboard')->assertRedirect();

    loginThroughSso();

    $this->get('/dashboard')->assertOk();
});

it('acknowledges a replayed webhook without acting on it again', function (): void {
    sendSloWebhook(['jti' => 'same'])->assertNoContent();
    loginThroughSso();

    sendSloWebhook(['jti' => 'same'])->assertNoContent();

    $this->get('/dashboard')->assertOk();
    Event::assertDispatchedTimes(SsoRemoteLogoutReceivedEvent::class, 1);
});

it('rejects unauthenticated webhooks', function (callable $headers): void {
    $body = '{"event":"logout","sub":"42","aud":"client-app","iat":0,"jti":"x"}';

    test()->call('POST', '/sso/slo-webhook', server: array_merge(['CONTENT_TYPE' => 'application/json'], $headers($body)), content: $body)
        ->assertUnauthorized();

    $this->get('/dashboard')->assertOk();
    Event::assertNotDispatched(SsoRemoteLogoutReceivedEvent::class);
})->with([
    'no headers' => [fn (string $body): array => []],
    'forged signature' => [fn (string $body): array => ['HTTP_X_SSO_TIMESTAMP' => (string) time(), 'HTTP_X_SSO_SIGNATURE' => str_repeat('0', 64)]],
    'signed with another secret' => [fn (string $body): array => ['HTTP_X_SSO_TIMESTAMP' => (string) time(), 'HTTP_X_SSO_SIGNATURE' => ssoSignatureHeaders($body, secret: 'other')['X-SSO-Signature']]],
    'stale timestamp' => [function (string $body): array {
        $headers = ssoSignatureHeaders($body, time() - 301);

        return ['HTTP_X_SSO_TIMESTAMP' => $headers['X-SSO-Timestamp'], 'HTTP_X_SSO_SIGNATURE' => $headers['X-SSO-Signature']];
    }],
]);

it('rejects signed payloads that are not a logout for this client', function (array $overrides): void {
    sendSloWebhook($overrides)->assertUnprocessable();

    $this->get('/dashboard')->assertOk();
})->with([
    'other client' => [['aud' => 'another-app']],
    'other event' => [['event' => 'login']],
    'missing sub' => [['sub' => null]],
    'missing jti' => [['jti' => null]],
]);

it('is reachable without a CSRF token or a session', function (): void {
    expect(Route::getRoutes()->getByName('sso-client.slo-webhook')->gatherMiddleware())
        ->not->toContain('web')
        ->not->toContain('auth');
});
