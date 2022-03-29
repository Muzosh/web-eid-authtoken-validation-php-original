<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the user certificate purpose is not client authentication.
 */
class UserCertificateWrongPurposeException extends AuthTokenException
{
	public function __construct()
	{
		parent::__construct("User certificate is not meant to be used as an authentication certificate");
	}
}
