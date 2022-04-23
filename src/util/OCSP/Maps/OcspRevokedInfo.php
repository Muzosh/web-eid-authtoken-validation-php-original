<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\CRLReason;

abstract class OcspRevokedInfo
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'revokedTime' => array(
                'type' => ASN1::TYPE_GENERALIZED_TIME,
            ),
            'revokedReason' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
            ) + CRLReason::MAP,
        ),
    );
}
