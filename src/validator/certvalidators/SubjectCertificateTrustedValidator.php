<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\util\DefaultClock;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificateTrustedValidator implements SubjectCertificateValidator
{
    private $logger;

    private TrustedCertificates $trustedCertificates;
    private X509 $subjectCertificateIssuerCertificate;

    public function __construct(
        TrustedCertificates $trustedCertificates
    ) {
        $this->logger = WebEidLogger::getLogger(
            self::class
        );
        $this->trustedCertificates = $trustedCertificates;
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
            $this->trustedCertificates,
            // $now
        );
        $this->logger->debug('Subject certificate is signed by a trusted CA');
    }

    public function getSubjectCertificateIssuerCertificate(): X509
    {
        return $this->subjectCertificateIssuerCertificate;
    }
}
