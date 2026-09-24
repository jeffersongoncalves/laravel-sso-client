<?php

namespace JeffersonGoncalves\SsoClient;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsoClientServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-sso-client')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigrations();
    }
}
