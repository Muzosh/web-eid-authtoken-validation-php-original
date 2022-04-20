<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;

abstract class OcspSingleResponse
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'certID' => OcspCertId::MAP,
            'certStatus' => OcspCertStatus::MAP,
            'thisUpdate' => array('type' => ASN1::TYPE_GENERALIZED_TIME),
            'nextUpdate' => array(
                'type' => ASN1::TYPE_GENERALIZED_TIME,
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
            ),
            'singleExtensions' => array(
                'constant' => 1,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
        ),
    );
}
