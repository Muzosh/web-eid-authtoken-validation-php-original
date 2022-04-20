<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\asn1\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Certificate;

abstract class OcspSignature
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'signatureAlgorithm' => AlgorithmIdentifier::MAP,
            'signature' => array('type' => ASN1::TYPE_BIT_STRING),
            'certs' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => Certificate::MAP,
            ),
        ),
    );
}
