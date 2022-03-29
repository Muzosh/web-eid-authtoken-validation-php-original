<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

class ChallengeNullOrEmptyException extends AuthTokenException
{
	public function __construct()
	{
		parent::__construct("Provided challenge is null or empty");
	}
}
