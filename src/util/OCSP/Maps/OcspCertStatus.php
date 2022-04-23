<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;

abstract class OcspCertStatus
{
    public const MAP = array(
        'type' => ASN1::TYPE_CHOICE,
        'children' => array(
            'good' => array(
                'constant' => 0,
                'implicit' => true,
                'type' => ASN1::TYPE_NULL,
            ),
            'revoked' => array(
                'constant' => 1,
                'implicit' => true,
            ) + OcspRevokedInfo::MAP,
            'unknown' => array(
                'constant' => 2,
                'implicit' => true,
            ) + OcspUnknownInfo::MAP,
        ),
    );
}
