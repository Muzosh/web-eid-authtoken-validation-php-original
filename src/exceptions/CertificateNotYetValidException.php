<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use Throwable;

/**
 * Thrown when the certificate's valid from date is in the future.
 */
class CertificateNotYetValidException extends AuthTokenException
{
    public function __construct(string $subject, Throwable $cause = null)
    {
        parent::__construct($subject.' certificate is not yet valid', $cause);
    }
}
