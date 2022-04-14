<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspService;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspService;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\OcspService;
use phpseclib3\File\X509;

class OcspServiceProvider
{
    private $designatedOcspService;
    private $aiaOcspServiceConfiguration;

    public function __construct(?DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration, AiaOcspServiceConfiguration $aiaOcspServiceConfiguration)
    {
        $this->designatedOcspService = !is_null($designatedOcspServiceConfiguration) ?
            new DesignatedOcspService($designatedOcspServiceConfiguration)
            : null;
        $this->aiaOcspServiceConfiguration = $aiaOcspServiceConfiguration;
    }

    /**
     * A static factory method that returns either the designated or AIA OCSP service instance depending on whether
     * the designated OCSP service is configured and supports the issuer of the certificate.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     *
     * @throws AuthTokenException           when AIA URL is not found in certificate
     * @throws CertificateEncodingException when certificate is invalid
     *
     * @return either the designated or AIA OCSP service instance
     */
    public function getService(X509 $certificate): OcspService
    {
        if (!is_null($this->designatedOcspService) && $this->designatedOcspService->supportsIssuerOf($certificate)) {
            return $this->designatedOcspService;
        }

        return new AiaOcspService($this->aiaOcspServiceConfiguration, $certificate);
    }
}
