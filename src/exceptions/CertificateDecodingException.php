<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use Throwable;

class CertificateDecodingException extends AuthTokenException
{
    public function __construct(Throwable $cause)
    {
        parent::__construct('Certificate decoding from Base64 or parsing failed', $cause);
    }
}
