<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** Network failure talking to the SSO Server, after retries. */
class SsoServerUnreachableException extends SsoClientException {}
