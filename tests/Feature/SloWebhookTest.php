<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use JeffersonGoncalves\SsoClient\Events\SsoRemoteLogoutReceivedEvent;
use JeffersonGoncalves\SsoClient\Tests\Support\RsaKeyset;

/**
 * @param  array<string, mixed>  $overrides
 */
function sendSloWebhook(array $overrides = [], ?string $signature = null): TestResponse
{
    $body = (string) json_encode(array_merge([
        'sid' => 'server-session-1',
        'sub' => 'user-42',
        'iat' => time(),
        'jti' => 'logout-1',
    ], $overrides));

    return test()->call('POST', '/sso/slo-webhook', server: [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_SSO_SIGNATURE' => $signature ?? hash_hmac('sha256', $body, 'shared-secret'),
    ], content: $body);
}

function localSessionData(string $id): string
{
    return app('session')->driver()->getHandler()->read($id);
}

beforeEach(function (): void {
    Event::fake([SsoRemoteLogoutReceivedEvent::class]);

    $keys = RsaKeyset::generate();
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($keys->jwks()),
        'sso.test/sso/token' => Http::response(['token' => $keys->sign(ssoClaims())]),
    ]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');
    $this->localSessionId = app('session')->driver()->getId();
});

it('destroys the local session bound to the server sid', function (): void {
    expect(localSessionData($this->localSessionId))->not->toBe('');

    sendSloWebhook()->assertNoContent();

    expect(localSessionData($this->localSessionId))->toBe('');
    Event::assertDispatched(SsoRemoteLogoutReceivedEvent::class, fn ($e): bool => $e->sid === 'server-session-1'
        && $e->sub === 'user-42'
        && $e->sessionDestroyed);
});

it('answers 204 for an unknown sid', function (): void {
    sendSloWebhook(['sid' => 'unknown'])->assertNoContent();

    expect(localSessionData($this->localSessionId))->not->toBe('');
    Event::assertDispatched(SsoRemoteLogoutReceivedEvent::class, fn ($e): bool => ! $e->sessionDestroyed);
});

it('rejects invalid webhooks without touching the session', function (array $overrides, ?string $signature): void {
    sendSloWebhook($overrides, $signature)->assertUnauthorized();

    expect(localSessionData($this->localSessionId))->not->toBe('');
    Event::assertNotDispatched(SsoRemoteLogoutReceivedEvent::class);
})->with([
    'forged signature' => [[], str_repeat('0', 64)],
    'missing signature' => [[], ''],
    'stale iat' => [['iat' => time() - 300], null],
    'missing jti' => [['jti' => null], null],
]);

it('rejects a replayed webhook', function (): void {
    sendSloWebhook(['sid' => 'unknown'])->assertNoContent();
    sendSloWebhook(['sid' => 'unknown'])->assertUnauthorized();
});

it('requires a sid', function (): void {
    sendSloWebhook(['sid' => null])->assertUnprocessable();
});
