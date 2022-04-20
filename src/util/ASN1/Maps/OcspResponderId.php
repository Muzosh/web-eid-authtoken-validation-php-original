<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Name;

abstract class OcspResponderId
{
    public const MAP = array(
        'type' => ASN1::TYPE_CHOICE,
        'children' => array(
            'byName' => array(
                'constant' => 1,
                'explicit' => true,
                'type' => Name::MAP,
            ),
            'byKey' => array(
                'constant' => 2,
                'explicit' => true,
                // SHA-1 hash of responder's public key (excluding the tag and length fields)
                'type' => ASN1::TYPE_OCTET_STRING,
            ),
        ),
    );
}
