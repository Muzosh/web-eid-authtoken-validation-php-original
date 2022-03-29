<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when authentication token signature validation fails.
 */
class AuthTokenSignatureValidationException extends AuthTokenException
{
	public function __construct()
	{
		parent::__construct("Token signature validation has failed. Check that the origin and nonce are correct.");
	}
}
