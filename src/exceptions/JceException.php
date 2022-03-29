<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

# TODO: whats this and how to recreate it in PHP?
# might not be needed
import java.security.GeneralSecurityException;

class JceException extends AuthTokenException {

	public function __construct(GeneralSecurityException $cause)
	{
		parent::__construct("Java Cryptography Extension loading or configuration failed", $cause);
	}
}
