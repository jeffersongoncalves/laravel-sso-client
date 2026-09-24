<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Exceptions;

/** The SSO email belongs to a local account that is not linked to this "sub". */
class AccountLinkingException extends SsoClientException {}
