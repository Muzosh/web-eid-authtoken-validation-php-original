<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
use DateTime;
use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;
use muzosh\web_eid_authtoken_validation_php\util\CertStore;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use phpseclib3\File\X509;

final class CertificateValidator
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function certificateIsValidOnDate(X509 $cert, DateTime $date, string $subject): void
    {
        if (!$cert->validateDate($date)) {
            if ($date < new DateTime($cert->getCurrentCert()['tbsCertificate']['validity']['notBefore']['utcTime'])) {
                throw new CertificateNotYetValidException($subject);
            }

            if ($date > new DateTime($cert->getCurrentCert()['tbsCertificate']['validity']['notAfter']['utcTime'])) {
                throw new CertificateExpiredException($subject);
            }
        }
    }

    public static function trustedCACertificatesAreValidOnDate(TrustedAnchors $trustedCACertificateAnchors, DateTime $date): void
    {
        foreach ($trustedCACertificateAnchors->getTrustedAnchors() as $cert) {
            if (!$cert instanceof X509) {
                throw new InvalidArgumentException('Invalid trustedCACertificateAnchor format.');
            }

            CertificateValidator::certificateIsValidOnDate($cert, $date, 'Trusted CA');
        }
    }

    public static function validateIsSignedByTrustedCA(
        X509 $certificate,
        TrustedAnchors $trustedCACertificateAnchors,
        CertStore $trustedCACertificateCertStore,
        DateTime $date
    ): X509 {
        // TODO: what this method does in java?
        return new X509();
    }

    public static function buildTrustAnchorsFromCertificates(array $certificates): TrustedAnchors
    {
        return new TrustedAnchors($certificates);
    }

    public static function buildCertStoreFromCertificates(array $certificates): CertStore
    {
        return new CertStore($certificates);
    }
}
