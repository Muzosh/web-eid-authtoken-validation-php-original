<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;

abstract class OcspOCSPResponseStatus
{
    public const MAP = array(
        'type' => ASN1::TYPE_ENUMERATED,
        'mapping' => array(
            0 => 'successful',
            1 => 'malformedRequest',
            2 => 'internalError',
            3 => 'tryLater',
            // 4 is not used
            5 => 'sigRequired',
            6 => 'unauthorized',
        ),
    );
}
