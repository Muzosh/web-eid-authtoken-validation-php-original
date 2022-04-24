<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;

abstract class OcspSingleResponses
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        // SEQUENCE OF XXX: phpseclib3\File\ASN1::asn1map needs min and max to know it is sequence of xxx - values are ignored
        'min' => 0,
        'max' => -1,
        'children' => OcspSingleResponse::MAP,
    );
}
