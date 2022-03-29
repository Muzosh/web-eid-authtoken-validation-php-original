<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when any of the configured disallowed policies is present in the user certificate.
 */
class UserCertificateDisallowedPolicyException extends AuthTokenException
{
	public function __construct()
	{
		parent::__construct("Disallowed user certificate policy");
	}
}
