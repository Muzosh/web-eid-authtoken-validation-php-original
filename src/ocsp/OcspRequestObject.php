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

use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspOCSPRequest;
use muzosh\web_eid_authtoken_validation_php\util\ASN1Util;
use phpseclib3\File\ASN1;

/**
 * Object for handling ASN1 encoded OCSPRequest from RFC 6960.
 */
class OcspRequestObject
{
    private array $ocspRequest = array();

    /**
     * Initialize base array skeleton.
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

	/**
	 * Insert ocsp request with CertificateID
	 * @param array $certificateId can be built by OcspUtil::getCertificateId() function
	 * @return void
	 */
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
