<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\util\CertStore;
use muzosh\web_eid_authtoken_validation_php\util\DefaultClock;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificateTrustedValidator implements SubjectCertificateValidator
{
    private $logger;

    private TrustedAnchors $trustedCACertificateAnchors;
    // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
    // private CertStore $trustedCACertificateCertStore;
    private X509 $subjectCertificateIssuerCertificate;

    public function __construct(
        TrustedAnchors $trustedCACertificateAnchors
        // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
        // CertStore $trustedCACertificateCertStore
    ) {
        $this->logger = WebEidLogger::getLogger(
            self::class
        );
        $this->trustedCACertificateAnchors = $trustedCACertificateAnchors;
        // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
        // $this->trustedCACertificateCertStore = $trustedCACertificateCertStore;
    }

    /**
     * Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
     *
     * @param subjectCertificate user certificate to be validated
     */
    public function validate(X509 $subjectCertificate): void
    {
        // Use the clock instance so that the date can be mocked in tests.
        $now = DefaultClock::getInstance()->now();
        $this->subjectCertificateIssuerCertificate = CertificateValidator::validateIsSignedByTrustedCA(
            $subjectCertificate,
            $this->trustedCACertificateAnchors,
            // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
            // $this->trustedCACertificateCertStore,
            // $now
        );
        $this->logger->debug('Subject certificate is signed by a trusted CA');
    }

    public function getSubjectCertificateIssuerCertificate(): X509
    {
        return $this->subjectCertificateIssuerCertificate;
    }
}
