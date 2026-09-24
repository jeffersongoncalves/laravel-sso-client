<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** OAuth "state" is missing or does not match the session (CSRF). */
class InvalidStateException extends SsoClientException {}
