<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;

abstract class OcspTbsResponseData
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
            'responderID' => OcspResponderId::MAP,
            'producedAt' => array('type' => ASN1::TYPE_GENERALIZED_TIME),
            'responses' => OcspSingleResponses::MAP,
            'responseExtensions' => array(
                'constant' => 1,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
        ),
    );
}
