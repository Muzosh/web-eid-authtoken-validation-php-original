<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
use phpseclib3\File\X509;
use UnexpectedValueException;

// in java code there is some special x500 formating?
// according to the tests there should be backslashes before dashes?
// why is it converting to JcaX509CertificateHolder object?
// TODO: ask author about this

final class CertificateData
{
    /**
     * __construct
     * Don't call this, all functions are static.
     *
     * @throws BadFunctionCallException
     */
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * getSubjectCN.
     */
    public static function getSubjectCN(X509 $certificate): string
    {
        return CertificateData::getSubjectField($certificate, 'id-at-commonName');
    }

    /**
     * getSubjectSurname.
     *
     * @param mixed $certificate
     */
    public static function getSubjectSurname(X509 $certificate): string
    {
        return CertificateData::getSubjectField($certificate, 'id-at-surname');
    }

    /**
     * getSubjectGivenName.
     *
     * @param mixed $certificate
     */
    public static function getSubjectGivenName(X509 $certificate): string
    {
        return CertificateData::getSubjectField($certificate, 'id-at-givenName');
    }

    /**
     * getSubjectIdCode.
     *
     * @param mixed $certificate
     */
    public static function getSubjectIdCode(X509 $certificate): string
    {
        return CertificateData::getSubjectField($certificate, 'id-at-serialNumber');
    }

    /**
     * getSubjectCountryCode.
     *
     * @param mixed $certificate
     */
    public static function getSubjectCountryCode(X509 $certificate): string
    {
        return CertificateData::getSubjectField($certificate, 'id-at-countryName');
    }

    /**
     * CertificateData::getSubjectField.
     *
     * @param mixed $certificate
     * @param mixed $fieldIdentifier
     */
    private static function getSubjectField(X509 $certificate, string $fieldIdentifier): string
    {
        $result = $certificate->getSubjectDNProp($fieldIdentifier);

        if ($result) {
            return $result[0];
        }

        throw new UnexpectedValueException('fieldIdentifier '.$fieldIdentifier.'not found in certificate: '.$certificate->getDN(X509::DN_STRING));
    }
}
