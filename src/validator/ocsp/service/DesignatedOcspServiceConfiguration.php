<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\util\X509Array;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use phpseclib3\File\X509;

class DesignatedOcspServiceConfiguration
{
    private Uri $ocspServiceAccessLocation;
    private X509 $responderCertificate;
    private bool $doesSupportNonce;
    private array $supportedIssuers;

    /**
     * Configuration of a designated OCSP service.
     *
     * @param ocspServiceAccessLocation the URL where the service is located
     * @param responderCertificate the service's OCSP responder certificate
     * @param supportedCertificateIssuers the certificate issuers supported by the service
     * @param doesSupportNonce true if the service supports the OCSP protocol nonce extension
     *
     * @throws OCSPCertificateException when an error occurs while extracting issuer names from certificates
     */
    public function __construct(Uri $ocspServiceAccessLocation, X509 $responderCertificate, X509Array $supportedCertificateIssuers, bool $doesSupportNonce)
    {
        $this->ocspServiceAccessLocation = $ocspServiceAccessLocation;
        $this->responderCertificate = $responderCertificate;
        $this->supportedIssuers = X509Array::getSubjectDNs($supportedCertificateIssuers);
        OcspResponseValidator::validateHasSigningExtension($responderCertificate);
        $this->doesSupportNonce = $doesSupportNonce;
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

    private function getSubject(X509 $certificate): string
    {
        // TODO: check this "C=EE,O=SK ID Solutions AS,organizationIdentifier=NTREE-10747013,CN=TEST of ESTEID2018"
        return $certificate->getSubjectDN(X509::DN_STRING);
    }
}
