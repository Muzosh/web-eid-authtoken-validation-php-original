<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;

abstract class OcspRequest
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'reqCert' => OcspCertId::MAP,
            'singleRequestExtensions' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
        ),
    );
}
