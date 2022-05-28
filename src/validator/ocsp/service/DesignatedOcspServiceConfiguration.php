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

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use GuzzleHttp\Psr7\Uri;
use LengthException;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use muzosh\web_eid_authtoken_validation_php\util\X509Array;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\File\X509;
use TypeError;

class DesignatedOcspServiceConfiguration
{
    private Uri $ocspServiceAccessLocation;
    private X509 $responderCertificate;
    private bool $doesSupportNonce;
    private array $supportedIssuers;

    /**
     * Configuration of a designated OCSP service.
     *
     * @throws InsufficientSetupException
     * @throws LengthException
     * @throws TypeError
     * @throws OCSPCertificateException when an error occurs while extracting issuer names from certificates
     */
    public function __construct(Uri $ocspServiceAccessLocation, X509 $responderCertificate, X509Array $supportedCertificateIssuers, bool $doesSupportNonce)
    {
        $this->ocspServiceAccessLocation = $ocspServiceAccessLocation;
        $this->responderCertificate = $responderCertificate;
        $this->supportedIssuers = X509Array::getSubjectDNs($supportedCertificateIssuers);
        $this->doesSupportNonce = $doesSupportNonce;

        OcspResponseValidator::validateHasSigningExtension($responderCertificate);
    }

    public function getOcspServiceAccessLocation(): Uri
    {
        return $this->ocspServiceAccessLocation;
    }

    public function getResponderCertificate(): X509
    {
        return $this->responderCertificate;
    }

    public function doesSupportNonce(): bool
    {
        return $this->doesSupportNonce;
    }

    public function supportsIssuerOf(X509 $certificate): bool
    {
        return in_array($certificate->getIssuerDN(X509::DN_STRING), $this->supportedIssuers, true);
    }
}
