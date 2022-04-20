<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;

abstract class OcspResponseData
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'childen' => array(
            'version' => array(
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                'mapping' => array('v1'),
                'default' => 'v1',
            ),
            'responderID' => OcspResponderId::MAP,
            'producedAt' => array('type' => ASN1::TYPE_GENERAL_STRING),
            'reponses' => array(
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => OcspSingleResponse::MAP,
            ),
            'responseExtensions' => array(
                'constant' => 1,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
        ),
    );
}
