<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** HMAC signature or JWT signature does not verify. */
class InvalidSignatureException extends SsoClientException {}
