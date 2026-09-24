<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Events;

use Illuminate\Foundation\Events\Dispatchable;

class SsoRemoteLogoutReceivedEvent
{
    use Dispatchable;

    /**
     * @param  string  $sub  The server's user id whose local sessions are now revoked.
     */
    public function __construct(
        public readonly string $sub,
    ) {}
}
