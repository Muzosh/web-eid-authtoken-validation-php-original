<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\util\DefaultClock;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificateExpiryValidator implements SubjectCertificateValidator
{
    private Logger $logger;
    private TrustedCertificates $trustedCertificates;

    public function __construct(TrustedCertificates $trustedCertificates)
    {
        $this->logger = WebEidLogger::getLogger(self::class);
        $this->trustedCertificates = $trustedCertificates;
    }

    /**
     * Checks the validity of the user certificate from the authentication token
     * and the validity of trusted CA certificates.
     *
     * @param subjectCertificate user certificate to be validated
     */
    public function validate(X509 $subjectCertificate): void
    {
        // Use the clock instance so that the date can be mocked in tests.
        $now = DefaultClock::getInstance()->now();
        CertificateValidator::trustedCACertificatesAreValidOnDate($this->trustedCertificates, $now);
        $this->logger->debug('CA certificates are valid.');
        CertificateValidator::certificateIsValidOnDate($subjectCertificate, $now, 'User');
        $this->logger->debug('User certificate is valid.');
    }
}
