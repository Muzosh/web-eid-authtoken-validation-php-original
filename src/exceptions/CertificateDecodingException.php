<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

class CertificateDecodingException extends AuthTokenException
{
    public function __construct(string $resource)
    {
        parent::__construct('Certificate parsing failed for '.$resource);
    }
}
