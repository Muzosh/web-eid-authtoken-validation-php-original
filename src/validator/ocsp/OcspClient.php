<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspResponseObject;

interface OcspClient
{
    public function request(Uri $url, string $requestBody): OcspResponseObject;
}
