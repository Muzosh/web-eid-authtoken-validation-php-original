<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;

abstract class OcspResponseStatus
{
    public const MAP = array(
        'type' => ASN1::TYPE_ENUMERATED,
        'mapping' => array(
            'successful',
            'malformedRequest',
            'internalError',
            'tryLater',
            // 4 is not used
            5 => 'sigRequired',
            'unauthorized',
        ),
    );
}
