<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\CertificateSerialNumber;

abstract class OcspCertId
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'hashAlgorithm' => AlgorithmIdentifier::MAP,
            // issuerNameHash is the hash of the issuer's distinguished name (DN). The hash shall be calculated over the DER encoding of the issuer's name field in the certificate being checked.
            'issuerNameHash' => array('type' => ASN1::TYPE_OCTET_STRING),
            // issuerKeyHash is the hash of the issuer's public key. The hash shall be calculated over the value (excluding tag and length) of the subject public key field in the issuer's certificate.
            'issuerKeyHash' => array('type' => ASN1::TYPE_OCTET_STRING),
            'serialNumber' => CertificateSerialNumber::MAP,
        ),
    );
}
