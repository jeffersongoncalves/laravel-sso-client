<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface SsoUserSynchronizerContract
{
    /**
     * Turn the verified SSO claims into the local user to log in.
     *
     * Implementations decide whether to persist the user, keep it in memory
     * only, or map roles/permissions from the payload.
     *
     * @param  array<string, mixed>  $ssoPayload  Verified token claims (sub, sid, jti, email, ...).
     */
    public function synchronize(array $ssoPayload): Authenticatable;
}
