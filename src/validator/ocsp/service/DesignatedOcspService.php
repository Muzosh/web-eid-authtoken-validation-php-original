<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use phpseclib3\File\X509;

/**
 * An OCSP service that uses a single designated OCSP responder.
 */
class DesignatedOcspService implements OcspService
{
    private DesignatedOcspServiceConfiguration $configuration;

    public function __construct(DesignatedOcspServiceConfiguration $configuration)
    {
        $this->configuration = $configuration;
    }

    public function doesSupportNonce(): bool
    {
        return $this->configuration->doesSupportNonce();
    }

    public function getAccessLocation(): Uri
    {
        return $this->configuration->getOcspServiceAccessLocation();
    }

    public function validateResponderCertificate(X509 $cert, DateTime $producedAt): void
    {
        // Certificate pinning is implemented simply by comparing the certificates or their public keys,
        // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
        if ($this->configuration->getResponderCertificate()->getCurrentCert() != $cert->getCurrentCert()) {
            throw new OCSPCertificateException('Responder certificate from the OCSP response is not equal to ' .
                'the configured designated OCSP responder certificate');
        }
        CertificateValidator::certificateIsValidOnDate($cert, $producedAt, 'Designated OCSP responder');
    }

    public function supportsIssuerOf(X509 $certificate): bool
    {
        return $this->configuration->supportsIssuerOf($certificate);
    }
}
