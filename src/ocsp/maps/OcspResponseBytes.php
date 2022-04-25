<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;

abstract class OcspResponseBytes
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'responseType' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
            'response' => array('type' => ASN1::TYPE_OCTET_STRING),
        ),
    );
}
