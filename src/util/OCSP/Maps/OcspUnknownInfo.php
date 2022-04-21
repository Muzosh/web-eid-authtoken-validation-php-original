<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;

abstract class OcspUnknownInfo
{
    public const MAP = array(
        'type' => ASN1::TYPE_NULL,
    );
}
