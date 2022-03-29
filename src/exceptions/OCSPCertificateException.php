<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use \Throwable;

class OCSPCertificateException extends AuthTokenException {

	public function __construct(string $message, Throwable $exception = null)
	{
		parent::__construct($message, $exception);
	}
}
