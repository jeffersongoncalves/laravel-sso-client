<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsoClient\Tests\Support\RsaKeyset;
use JeffersonGoncalves\SsoClient\Tests\Support\User;

it('ends the local session and sends the browser to the server logout', function (): void {
    $keys = RsaKeyset::generate();
    $token = $keys->sign(ssoClaims());
    Http::fake([
        'sso.test/.well-known/jwks.json' => Http::response($keys->jwks()),
        'sso.test/sso/token' => Http::response(['access_token' => $token]),
    ]);
    $this->get('/sso/callback?code=c&state='.beginSsoLogin())->assertRedirect('/');

    $location = (string) $this->post('/sso/logout')->assertRedirect()->headers->get('Location');

    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
    expect($location)->toStartWith('https://sso.test/sso/logout?')
        ->and($query)->toBe([
            'client_id' => 'client-app',
            'token_hint' => $token,
            'post_logout_redirect_uri' => url('/'),
        ])
        ->and(session('sso-client.access_token'))->toBeNull();
    $this->assertGuest();
});

it('uses the configured post logout redirect uri', function (): void {
    config(['sso-client.post_logout_redirect_uri' => 'http://localhost/goodbye']);
    $this->actingAs(User::create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'x']))
        ->withSession(['sso-client.access_token' => 'last.jwt.token']);

    $location = (string) $this->post('/sso/logout')->headers->get('Location');

    expect($location)->toContain('post_logout_redirect_uri='.urlencode('http://localhost/goodbye'));
});

it('only logs out locally when the session has no SSO token', function (): void {
    $this->actingAs(User::create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'x']));

    $this->post('/sso/logout')->assertRedirect(url('/'));

    $this->assertGuest();
});

it('only accepts POST, so a link or image cannot log users out', function (): void {
    $this->get('/sso/logout')->assertMethodNotAllowed();
});
