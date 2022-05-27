<?php

/* The MIT License (MIT)
*
* Copyright (c) 2022 Petr Muzikant <pmuzikant@email.cz>
*
* > Permission is hereby granted, free of charge, to any person obtaining a copy
* > of this software and associated documentation files (the "Software"), to deal
* > in the Software without restriction, including without limitation the rights
* > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* > copies of the Software, and to permit persons to whom the Software is
* > furnished to do so, subject to the following conditions:
* >
* > The above copyright notice and this permission notice shall be included in
* > all copies or substantial portions of the Software.
* >
* > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* > THE SOFTWARE.
*/

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp;

use DateTime;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspTbsResponseData;
use muzosh\web_eid_authtoken_validation_php\util\ASN1Util;
use phpseclib3\File\ASN1;

/**
 * Object for handling ASN1 encoded BasicOCSPResponse from RFC6960.
 */
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
        return ASN1Util::removeFirstByte($this->ocspBasicResponse['signature']);
    }

    public function getEncodedResponseData(): string
    {
        return ASN1::encodeDER($this->ocspBasicResponse['tbsResponseData'], OcspTbsResponseData::MAP);
    }

    public function getProducedAt(): DateTime
    {
        return new DateTime($this->ocspBasicResponse['tbsResponseData']['producedAt']);
    }

    /**
     * ! currently works only for shaXXXWithXXX (example: sha256WithRSAEncryption)\
     * this method assumes the ocspBasicResponse translated the OID to algorithm name during its creation.
     *
     * @throws OCSPCertificateException
     */
    public function getSignatureAlgorithm(): string
    {
        $algorithm = strtolower($this->ocspBasicResponse['signatureAlgorithm']['algorithm']);

        if (false !== ($pos = strpos($algorithm, 'sha3-'))) {
            return substr($algorithm, $pos, 8);
        }
        if (false !== ($pos = strpos($algorithm, 'sha'))) {
            return substr($algorithm, $pos, 6);
        }

        throw new OCSPCertificateException(
            'Not implemented yet. Add algorithm name in ASN1Util::loadOIDs for OID'.
            $this->ocspBasicResponse['signatureAlgorithm']['algorithm']
        );
    }

	/**
	 * Get ID_PKIX_OCSP_NONCE extension value
	 * @return string
	 * @throws OCSPCertificateException
	 */
    public function getNonceExtension(): string
    {
        $value = current(
            array_filter(
                $this->ocspBasicResponse['tbsResponseData']['responseExtensions'],
                function ($extension) {
                    return ASN1Util::ID_PKIX_OCSP_NONCE == ASN1::getOID($extension['extnId']);
                }
            )
        )['extnValue'];

        if ($value) {
            return $value;
        }

        throw new OCSPCertificateException(
            'Not implemented yet. Update algorithm name in ASN1Util::loadOIDs for id-pkix-ocsp-nonce.'
        );
    }
}
