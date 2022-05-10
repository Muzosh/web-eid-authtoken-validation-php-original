<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp;

use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspOCSPRequest;
use phpseclib3\File\ASN1;

class OcspRequestObject
{
    private array $ocspRequest = array();

    /**
     * Default Constructor.
     *
     * @return OcspRequestObject
     */
    public function __construct()
    {
        // create base array for request
        $this->ocspRequest = array(
            'tbsRequest' => array(
                'version' => 'v1',
                'requestList' => array(),
                'requestExtensions' => array(),
            ),
        );
    }

    public function getEncodedDER(): string
    {
        return ASN1::encodeDER($this->ocspRequest, OcspOCSPRequest::MAP);
    }

    public function addRequest(array $certificateId): void
    {
        $request = array(
            'reqCert' => $certificateId,
        );

        $this->ocspRequest['tbsRequest']['requestList'][] = $request;
    }

    public function addNonceExtension(string $nonceString): void
    {
        $nonceExtension = array(
            'extnId' => ASN1Util::ID_PKIX_OCSP_NONCE,
            'critical' => false,
            'extnValue' => $nonceString,
        );

        $this->ocspRequest['tbsRequest']['requestExtensions'][] = $nonceExtension;
    }

    public function getNonceExtension(): string
    {
        return current(
            array_filter(
                $this->ocspRequest['tbsRequest']['requestExtensions'],
                function ($extension) {
                    return ASN1Util::ID_PKIX_OCSP_NONCE == $extension['extnId'];
                }
            )
        )['extnValue'];
    }
}
