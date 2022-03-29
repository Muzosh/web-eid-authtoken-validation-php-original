<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use \Throwable;

/**
 * Thrown when authentication token parsing fails.
 */
class AuthTokenParseException extends AuthTokenException
{
	public function __construct(string $message, Throwable $cause = null)
	{
		parent::__construct($message, $cause);
	}
}
