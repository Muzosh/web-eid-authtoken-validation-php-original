<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use \Throwable;
use \Exception;

/**
 * Base class for all authentication token validation exceptions.
 */
abstract class AuthTokenException extends Exception
{
	protected function __construct(string $message, Throwable $cause = null)
	{
		if (is_null($cause)) {
			parent::__construct($message);
		} else {
			parent::__construct($message, $cause->getCode(), $cause);
		}
	}
}
