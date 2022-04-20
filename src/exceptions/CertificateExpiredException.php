<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use Throwable;

/**
 * Thrown when the certificate's valid until date is in the past.
 */
class CertificateExpiredException extends AuthTokenException
{
    public function __construct(string $subject, Throwable $cause = null)
    {
        parent::__construct($subject.' certificate has expired', $cause);
    }
}
