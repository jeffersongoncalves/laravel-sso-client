<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Events;

use Illuminate\Foundation\Events\Dispatchable;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;

class SsoLoginFailedEvent
{
    use Dispatchable;

    public function __construct(
        public readonly SsoClientException $exception,
    ) {}
}
