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
            // "testing" = in-memory SQLite; CI also runs with DB_CONNECTION=mysql|pgsql.
            'database.default' => env('DB_CONNECTION', 'testing'),
            'cache.default' => 'array',
            'session.driver' => 'array',
            'auth.providers.users.model' => User::class,
            'sso-client.server_url' => 'https://sso.test',
            'sso-client.client_id' => 'client-app',
            'sso-client.client_secret' => 'shared-secret',
        ]);
    }
}
