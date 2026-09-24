<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

class UserSynchronizedEvent
{
    use Dispatchable;

    /**
     * @param  array<string, mixed>  $ssoPayload
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly array $ssoPayload,
    ) {}
}
