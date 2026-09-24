<?php

namespace JeffersonGoncalves\SsoClient\Tests;

use JeffersonGoncalves\SsoClient\SsoClientServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SsoClientServiceProvider::class,
        ];
    }
}
