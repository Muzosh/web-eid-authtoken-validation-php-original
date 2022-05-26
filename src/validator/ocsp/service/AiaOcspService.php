<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
use phpseclib3\File\X509;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
class AiaOcspService implements OcspService
{
    private TrustedCertificates $trustedCertificates;
    private Uri $url;
    private bool $supportsNonce;

    public function __construct(AiaOcspServiceConfiguration $configuration, X509 $certificate)
    {
        $this->trustedCertificates = $configuration->getTrustedCertificates();
        $this->url = self::getOcspAiaUrlFromCertificate($certificate);
        $this->supportsNonce = !$configuration->getNonceDisabledOcspUrls()->inArray($this->url);
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
        CertificateValidator::validateIsSignedByTrustedCA($cert, $this->trustedCertificates); // , $this->trustedCACertificateCertStore, $this->producedAt);
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
