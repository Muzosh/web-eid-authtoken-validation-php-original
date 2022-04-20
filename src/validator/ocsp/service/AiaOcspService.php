<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\util\CertStore;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
use phpseclib3\File\X509;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
class AiaOcspService implements OcspService
{
    private TrustedAnchors $trustedCACertificateAnchors;
    // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
    // private CertStore $trustedCACertificateCertStore;
    private Uri $url;
    private bool $supportsNonce;

    public function __construct(AiaOcspServiceConfiguration $configuration, X509 $certificate)
    {
        $this->trustedCACertificateAnchors = $configuration->getTrustedCACertificateAnchors();
        // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
        // $this->trustedCACertificateCertStore = $configuration->getTrustedCACertificateCertStore();
        $this->url = AiaOcspService::getOcspAiaUrlFromCertificate($certificate);
        $this->supportsNonce = !in_array($this->url, $configuration->getNonceDisabledOcspUrls());
    }

    public function doesSupportNonce(): bool
    {
        return $this->supportsNonce;
    }

    public function getAccessLocation(): Uri
    {
        return $this->url;
    }

    public function validateResponderCertificate(X509 $cert, DateTime $producedAt): void
    {
        CertificateValidator::certificateIsValidOnDate($cert, $producedAt, 'AIA OCSP responder');
        // Trusted certificates' validity has been already verified in validateCertificateExpiry().
        OcspResponseValidator::validateHasSigningExtension($cert);
        CertificateValidator::validateIsSignedByTrustedCA($cert, $this->trustedCACertificateAnchors); // , $this->trustedCACertificateCertStore, $this->producedAt);
    }

    private static function getOcspAiaUrlFromCertificate(X509 $certificate): Uri
    {
        $uri = OcspUrl::getOcspUri($certificate);
        if (null == $uri || false === $uri) {
            throw new UserCertificateOCSPCheckFailedException('Getting the AIA OCSP responder field from the certificate failed');
        }

        return $uri;
    }
}
