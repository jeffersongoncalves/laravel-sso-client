<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** Token or webhook is outside its validity window. */
class TokenExpiredException extends SsoClientException {}
