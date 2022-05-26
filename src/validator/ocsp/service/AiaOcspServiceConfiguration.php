<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use muzosh\web_eid_authtoken_validation_php\util\CertStore;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
use muzosh\web_eid_authtoken_validation_php\util\UriUniqueArray;

class AiaOcspServiceConfiguration
{
    private UriUniqueArray $nonceDisabledOcspUrls;
    private TrustedCertificates $trustedCertificates;

    public function __construct(UriUniqueArray $nonceDisabledOcspUrls, TrustedCertificates $trustedCertificates)// , CertStore $trustedCACertificateCertStore)
    {
        $this->nonceDisabledOcspUrls = $nonceDisabledOcspUrls;
        $this->trustedCertificates = $trustedCertificates;
    }

    public function getNonceDisabledOcspUrls(): UriUniqueArray
    {
        return $this->nonceDisabledOcspUrls;
    }

    public function getTrustedCertificates(): TrustedCertificates
    {
        return $this->trustedCertificates;
    }
}
