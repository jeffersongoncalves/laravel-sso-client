<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** Token was issued by another server ("iss") or for another client ("aud"). */
class SsoClientMismatchException extends SsoClientException {}
