<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;
use JeffersonGoncalves\SsoClient\Exceptions\AccountLinkingException;
use JeffersonGoncalves\SsoClient\Tests\Support\RsaKeyset;
use JeffersonGoncalves\SsoClient\Tests\Support\User;

function synchronizeSso(array $claims = []): User
{
    /** @var User */
    return app(SsoUserSynchronizerContract::class)->synchronize(ssoClaims($claims));
}

it('creates a new user linked to the server sub', function (): void {
    $user = synchronizeSso();

    expect($user->only(['name', 'email', 'sso_id']))->toBe(['name' => 'Ada Lovelace', 'email' => 'ada@example.com', 'sso_id' => '42'])
        ->and($user->password)->not->toBeEmpty();
});

it('finds a linked user by sub even after the email changed on the server', function (): void {
    $linked = synchronizeSso();

    $user = synchronizeSso(['email' => 'ada@new-domain.com', 'name' => 'Ada King']);

    expect($user->is($linked))->toBeTrue()
        ->and($user->email)->toBe('ada@new-domain.com')
        ->and(User::count())->toBe(1);
});

it('refuses to take over an existing unlinked account by email', function (): void {
    $local = User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);

    expect(fn () => synchronizeSso())->toThrow(AccountLinkingException::class);

    expect($local->fresh()->only(['name', 'sso_id']))->toBe(['name' => 'Local Admin', 'sso_id' => null]);
});

it('links an existing account by email only when explicitly allowed', function (): void {
    config(['sso-client.user.link_existing_users_by_email' => true]);
    $local = User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);

    $user = synchronizeSso();

    expect($user->is($local))->toBeTrue()->and($user->sso_id)->toBe('42');
});

it('never links by email when the server says the email is not verified', function (): void {
    config(['sso-client.user.link_existing_users_by_email' => true]);
    $local = User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);

    expect(fn () => synchronizeSso(['email_verified' => false]))->toThrow(AccountLinkingException::class)
        ->and(fn () => synchronizeSso(['email_verified' => 'true']))->toThrow(AccountLinkingException::class);

    expect($local->fresh()->sso_id)->toBeNull();
});

it('trusts the explicit config when an older server omits email_verified', function (): void {
    config(['sso-client.user.link_existing_users_by_email' => true]);
    $local = User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);
    $claims = ssoClaims();
    unset($claims['email_verified']);

    $user = app(SsoUserSynchronizerContract::class)->synchronize($claims);

    expect($user->is($local))->toBeTrue()->and($user->sso_id)->toBe('42');
});

it('still creates brand new users whose email is not verified', function (): void {
    expect(synchronizeSso(['email_verified' => false])->sso_id)->toBe('42');
});

it('refuses unverified emails for existing users in legacy mode', function (): void {
    config(['sso-client.user.sso_id_column' => null]);
    User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);

    expect(fn () => synchronizeSso(['email_verified' => false]))->toThrow(AccountLinkingException::class);
});

it('never re-links an account already linked to another sub', function (): void {
    config(['sso-client.user.link_existing_users_by_email' => true]);
    synchronizeSso(['sub' => '7']);

    expect(fn () => synchronizeSso(['sub' => '42']))->toThrow(AccountLinkingException::class);

    expect(User::sole()->sso_id)->toBe('7');
});

it('matches by email only in the opt-in legacy mode', function (): void {
    config(['sso-client.user.sso_id_column' => null]);
    $local = User::create(['name' => 'Old Name', 'email' => 'ada@example.com', 'password' => 'secret']);

    $user = synchronizeSso();

    expect($user->is($local))->toBeTrue()->and($user->name)->toBe('Ada Lovelace')->and($user->sso_id)->toBeNull();
});

it('fails the SSO login with a 401 instead of taking over the account', function (): void {
    User::create(['name' => 'Local Admin', 'email' => 'ada@example.com', 'password' => 'secret']);
    $keys = RsaKeyset::generate();
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($keys->jwks()),
        'sso.test/sso/token' => Http::response(['access_token' => $keys->sign(ssoClaims())]),
    ]);

    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertUnauthorized();

    $this->assertGuest();
});
