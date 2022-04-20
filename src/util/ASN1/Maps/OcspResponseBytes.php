<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;

abstract class OcspResponseBytes
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'childen' => array(
            'responseType' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
            'response' => array(ASN1::TYPE_OCTET_STRING),
        ),
    );
}
