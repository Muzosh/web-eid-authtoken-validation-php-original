<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
use DateTime;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
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
        foreach ($trustedCACertificateAnchors->getCertificates() as $cert) {
            CertificateValidator::certificateIsValidOnDate($cert, $date, 'Trusted CA');
        }
    }

    public static function validateIsSignedByTrustedCA(
        X509 $certificate,
        TrustedAnchors $trustedCACertificateAnchors
        // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
        // CertStore $trustedCACertificateCertStore
        // DateTime $date - cannot be used in X509 object? maybe setStartDate and setEndDate functions?
    ): X509 {
        foreach ($trustedCACertificateAnchors->getCertificates() as $trustedCertificate) {
            $certificate->loadCA($trustedCertificate->saveX509($trustedCertificate->getCurrentCert(), X509::FORMAT_PEM));
        }

        // ? Do we want to disable fetching of isser certificates of loaded intermediate certs?
        // $certificate->disableURLFetch();

        if ($certificate->validateSignature()) {
            return end($certificate->getChain());
        }

        throw new CertificateNotTrustedException($certificate);
    }

    public static function buildTrustAnchorsFromCertificates(array $certificates): TrustedAnchors
    {
        return new TrustedAnchors($certificates);
    }

    // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
    // public static function buildCertStoreFromCertificates(array $certificates): CertStore
    // {
    // 	// TODO: how to ensure that treat safety Java comment is talking about?
    //     return new CertStore($certificates, null);
    // }
}
