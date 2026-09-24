<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\SsoClient\SsoClientServiceProvider;
use JeffersonGoncalves\SsoClient\Tests\Support\User;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        // MySQL/PostgreSQL keep tables between tests; in-memory SQLite does not.
        Schema::dropIfExists('users');
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    protected function getPackageProviders($app): array
    {
        return [
            SsoClientServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set([
            'app.key' => 'base64:'.base64_encode(random_bytes(32)),
            'database.default' => 'testing',
            'database.connections.testing' => $this->testing_connection(),
            'cache.default' => 'array',
            'session.driver' => 'array',
            'auth.providers.users.model' => User::class,
            'sso-client.server_url' => 'https://sso.test',
            'sso-client.client_id' => 'client-app',
            'sso-client.client_secret' => 'shared-secret',
        ]);
    }

    /**
     * In-memory SQLite locally; CI (tests.yml) sets SSO_CLIENT_TEST_DB_* to run
     * the same suite against MySQL and PostgreSQL. Not the plain DB_* names:
     * Testbench sets DB_CONNECTION=testing itself and would always win.
     *
     * @return array<string, mixed>
     */
    protected function testing_connection(): array
    {
        $driver = env('SSO_CLIENT_TEST_DB_DRIVER', 'sqlite');

        if ($driver === 'sqlite') {
            return ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true];
        }

        return [
            'driver' => $driver,
            'host' => env('SSO_CLIENT_TEST_DB_HOST', '127.0.0.1'),
            'port' => env('SSO_CLIENT_TEST_DB_PORT'),
            'database' => env('SSO_CLIENT_TEST_DB_DATABASE', 'testing'),
            'username' => env('SSO_CLIENT_TEST_DB_USERNAME', 'root'),
            'password' => env('SSO_CLIENT_TEST_DB_PASSWORD', ''),
            'charset' => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'prefix' => '',
        ];
    }
}
