<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp;

use DateTime;
use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspTbsResponseData;
use phpseclib3\File\ASN1;

class BasicResponseObject
{
    private array $ocspBasicResponse = array();

    public function __construct(array $ocspBasicResponse)
    {
        $this->ocspBasicResponse = $ocspBasicResponse;
    }

    public function getResponses(): array
    {
        return $this->ocspBasicResponse['tbsResponseData']['responses'];
    }

    public function getCerts(): array
    {
        return $this->ocspBasicResponse['certs'];
    }

    public function getSignature(): string
    {
        return ASN1Util::removeZeroPaddingFromFirstByte($this->ocspBasicResponse['signature']);
    }

    public function getEncodedResponseData(): string
    {
        return ASN1::encodeDER($this->ocspBasicResponse['tbsResponseData'], OcspTbsResponseData::MAP);
    }

    public function getProducedAt(): DateTime
    {
        return new DateTime($this->ocspBasicResponse['tbsResponseData']['producedAt']);
    }

    public function getSignatureAlgorithm(): string
    {
        // ! works only for SHA and known OIDs
        // TODO: definitely needs some other approach
        // example input: sha256WithRSAEncryption
        $algorithm = strtolower($this->ocspBasicResponse['signatureAlgorithm']['algorithm']);

        if (false !== ($pos = strpos($algorithm, 'sha3-'))) {
            return substr($algorithm, $pos, 8);
        }
        if (false !== ($pos = strpos($algorithm, 'sha'))) {
            return substr($algorithm, $pos, 6);
        }

        return 'sha256';
    }

    public function getNonceExtension(): string
    {
        return current(
            array_filter(
                $this->ocspBasicResponse['tbsResponseData']['responseExtensions'],
                function ($extension) {
                    return ASN1Util::ID_PKIX_OCSP_NONCE == $extension['extnId'];
                }
            )
        )['extnValue'];
    }
}
