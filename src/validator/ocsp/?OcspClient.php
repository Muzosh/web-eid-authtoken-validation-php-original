<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

interface OcspClient {

    function request(array $url, OCSPReq $request): OCSPResp;

}
