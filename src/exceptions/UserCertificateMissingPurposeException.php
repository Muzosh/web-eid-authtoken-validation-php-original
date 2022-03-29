<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the user certificate purpose field is missing or empty.
 */
class UserCertificateMissingPurposeException extends AuthTokenException {
	public function __construct()
	{
		parent::__construct("User certificate purpose is missing");
	}
}
