<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use Throwable;

/**
 * Thrown when user certificate revocation check with OCSP fails.
 */
class UserCertificateOCSPCheckFailedException extends AuthTokenException
{
    public function __construct(string $message, Throwable $cause = null)
    {
        parent::__construct('User certificate revocation check has failed: '.$message, $cause);
    }
}
