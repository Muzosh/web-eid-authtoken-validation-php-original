<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\GeneralName;

abstract class OcspTbsRequest
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'version' => array(
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                'mapping' => array('v1'),
                'default' => 'v1',
            ),
            'requestorName' => array(
                'constant' => 1,
                'optional' => true,
                'explicit' => true,
            ) + GeneralName::MAP,
            'requestList' => array(
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => OcspRequest::MAP, ),
            'requestExtensions' => array(
                'constant' => 2,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
        ),
    );
}
