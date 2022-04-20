<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;

abstract class OcspResponse
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'responseStatus' => OcspTbsRequest::MAP,
            'responseBytes' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
            ) + OcspResponseBytes::MAP,
        ),
    );
}
