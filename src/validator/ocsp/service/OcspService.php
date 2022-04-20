<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;

interface OcspService
{
    public function doesSupportNonce(): bool;

    public function getAccessLocation(): Uri;

    public function validateResponderCertificate(X509 $cert, DateTime $date): void;
}
