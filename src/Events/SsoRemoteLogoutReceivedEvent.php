<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Events;

use Illuminate\Foundation\Events\Dispatchable;

class SsoRemoteLogoutReceivedEvent
{
    use Dispatchable;

    public function __construct(
        public readonly string $sid,
        public readonly ?string $sub,
        public readonly bool $sessionDestroyed,
    ) {}
}
