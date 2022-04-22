<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;

abstract class OcspBasicOcspResponse
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'tbsResponseData' => OcspTbsResponseData::MAP,
            'signatureAlgorithm' => AlgorithmIdentifier::MAP,
            // The value for signature SHALL be computed on the hash of the DER encoding of ResponseData.
            'signature' => array('type' => ASN1::TYPE_BIT_STRING),
            'certs' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
            ) + OcspCertificates::MAP,
        ),
    );
}
