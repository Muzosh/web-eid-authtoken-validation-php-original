<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use phpseclib3\File\X509;

interface OcspService
{
    public function doesSupportNonce(): bool;

    public function getAccessLocation(): array;

    public function validateResponderCertificate(X509 $cert, DateTime $date): void;
}
