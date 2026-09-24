<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Tests;

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoServer\Controllers\TokenExchangeController;
use JeffersonGoncalves\SsoServer\Controllers\UserInfoController;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;
use JeffersonGoncalves\SsoServer\SsoServerServiceProvider;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs the real laravel-sso-server (dev dependency) in the same app as the
 * client, with the client's outgoing HTTP calls routed into the server's code.
 * The server logs users in on the separate "idp" guard.
 */
class InteropTestCase extends TestCase
{
    protected string $keysPath;

    protected SsoClient $ssoClient;

    protected function setUp(): void
    {
        parent::setUp();

        foreach (['create_sso_active_sessions_table', 'create_sso_clients_table'] as $name) {
            (require $this->serverMigration($name))->down();
        }

        foreach (['create_sso_clients_table', 'create_sso_active_sessions_table'] as $name) {
            (require $this->serverMigration($name))->up();
        }

        $this->artisan('sso-server:keys')->assertSuccessful();

        // Same flow as `php artisan sso-server:client`.
        $this->ssoClient = SsoClient::create([
            'name' => 'Client App',
            'client_id' => (string) Str::uuid(),
            'client_secret' => Str::random(64),
            'redirect_uri' => route('sso-client.callback'),
            'slo_webhook_url' => route('sso-client.slo-webhook'),
            'is_active' => true,
        ]);

        config([
            'sso-client.client_id' => $this->ssoClient->client_id,
            'sso-client.client_secret' => $this->ssoClient->client_secret,
        ]);

        Http::fake(fn (ClientRequest $request) => $this->routeToServer($request));
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->keysPath);

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), SsoServerServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $this->keysPath = sys_get_temp_dir().'/sso-client-interop-keys-'.Str::random(8);

        $app['config']->set([
            'app.url' => 'https://idp.test',
            'auth.guards.idp' => ['driver' => 'session', 'provider' => 'users'],
            'queue.default' => 'sync',
            'sso-server.guard' => 'idp',
            'sso-server.keys.path' => $this->keysPath,
            'sso-server.keys.openssl_config' => __DIR__.'/Support/openssl.cnf',
            'sso-client.server_url' => 'https://idp.test',
            // actingAs(..., 'idp') switches the default guard; keep the client on "web".
            'sso-client.guard' => 'web',
        ]);
    }

    /**
     * Server endpoints run their real controllers; the SLO webhook the server
     * sends back goes through the client's full HTTP stack.
     */
    protected function routeToServer(ClientRequest $request): mixed
    {
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        $server = ['HTTP_ACCEPT' => 'application/json'];

        foreach ($request->headers() as $name => $values) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $values[0];
        }

        $response = match ($path) {
            '/.well-known/jwks.json' => response()->json(app(ServerTokenManager::class)->jwks()),
            '/sso/token' => app(TokenExchangeController::class)(
                Request::create($request->url(), 'POST', $request->data(), server: $server),
                app(ServerTokenManager::class),
            ),
            '/sso/userinfo' => app(UserInfoController::class)(
                Request::create($request->url(), 'GET', server: $server),
                app(ServerTokenManager::class),
            ),
            '/sso/slo-webhook' => $this->call('POST', $path, server: $server + ['CONTENT_TYPE' => 'application/json'], content: $request->body())->baseResponse,
            default => throw new RuntimeException("Unexpected SSO call to {$request->url()}"),
        };

        return $this->toClientResponse($response);
    }

    protected function toClientResponse(Response $response): mixed
    {
        return Http::response((string) $response->getContent(), $response->getStatusCode(), $response->headers->all());
    }

    protected function serverMigration(string $name): string
    {
        return __DIR__."/../vendor/jeffersongoncalves/laravel-sso-server/database/migrations/{$name}.php.stub";
    }
}
