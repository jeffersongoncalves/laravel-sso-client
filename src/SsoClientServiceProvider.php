<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Routing\Router;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;
use JeffersonGoncalves\SsoClient\Http\Middleware\EnsureSsoAuthenticated;
use JeffersonGoncalves\SsoClient\Services\DefaultUserSynchronizer;
use JeffersonGoncalves\SsoClient\Services\SsoClientManager;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsoClientServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-sso-client')
            ->hasConfigFile('sso-client')
            ->hasRoute('web');
    }

    public function packageRegistered(): void
    {
        $this->app->bind(SsoUserSynchronizerContract::class, function ($app): SsoUserSynchronizerContract {
            /** @var class-string<SsoUserSynchronizerContract> $class */
            $class = $app->make(ConfigRepository::class)->get('sso-client.synchronizer', DefaultUserSynchronizer::class);

            return $app->make($class);
        });

        $this->app->bind(SsoClientManager::class);
    }

    public function packageBooted(): void
    {
        $this->app->make(Router::class)->aliasMiddleware('sso.auth', EnsureSsoAuthenticated::class);
    }
}
