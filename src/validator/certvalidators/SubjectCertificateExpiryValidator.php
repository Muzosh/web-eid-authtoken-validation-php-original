<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\util\DefaultClock;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificateExpiryValidator
{
    private $logger;
    private $trustedCACertificateAnchors;

    public function __construct(TrustedAnchors $trustedCACertificateAnchors)
    {
        $this->logger = WebEidLogger::getLogger(SubjectCertificateExpiryValidator::class);
        $this->trustedCACertificateAnchors = $trustedCACertificateAnchors;
    }

    /**
     * Checks the validity of the user certificate from the authentication token
     * and the validity of trusted CA certificates.
     *
     * @param subjectCertificate user certificate to be validated
     */
    public function validateCertificateExpiry(X509 $subjectCertificate): void
    {
        // Use the clock instance so that the date can be mocked in tests.
        $now = DefaultClock::getInstance()->now();
        CertificateValidator::trustedCACertificatesAreValidOnDate($this->trustedCACertificateAnchors, $now);
        $this->logger->debug('CA certificates are valid.');
        CertificateValidator::certificateIsValidOnDate($subjectCertificate, $now, 'User');
        $this->logger->debug('User certificate is valid.');
    }
}
