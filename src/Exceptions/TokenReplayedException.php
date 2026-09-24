<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** The "jti" was already consumed (one-time use). */
class TokenReplayedException extends SsoClientException {}
