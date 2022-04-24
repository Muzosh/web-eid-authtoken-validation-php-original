<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\testutil;

use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\util\UriUniqueArray;
use muzosh\web_eid_authtoken_validation_php\util\X509Array;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;

class OcspServiceMaker
{
    private const TEST_OCSP_ACCESS_LOCATION = 'http://demo.sk.ee/ocsp';
    private const TEST_ESTEID_2015 = 'http://aia.demo.sk.ee/esteid2015';

    public static function getAiaOcspServiceProvider(): OcspServiceProvider
    {
        return new OcspServiceProvider(null, self::getAiaOcspServiceConfiguration());
    }

    public static function getDesignatedOcspServiceProvider(bool $doesSupportNonce = true, string $ocspServiceAccessLocation = self::TEST_OCSP_ACCESS_LOCATION): OcspServiceProvider
    {
        return new OcspServiceProvider(self::getDesignatedOcspServiceConfiguration($doesSupportNonce, $ocspServiceAccessLocation), self::getAiaOcspServiceConfiguration());
    }

    public static function getDesignatedOcspServiceConfiguration(bool $doesSupportNonce = true, string $ocspServiceAccessLocation = self::TEST_OCSP_ACCESS_LOCATION): DesignatedOcspServiceConfiguration
    {
        return new DesignatedOcspServiceConfiguration(
            new Uri($ocspServiceAccessLocation),
            Certificates::getTestSkOcspResponder2020(),
            new X509Array(Certificates::getTestEsteid2018CA(), Certificates::getTestEsteid2015CA()),
            $doesSupportNonce
        );
    }

    private static function getAiaOcspServiceConfiguration(): AiaOcspServiceConfiguration
    {
        return new AiaOcspServiceConfiguration(
            new UriUniqueArray(new Uri(OcspUrl::AIA_ESTEID_2015_URL), new Uri(self::TEST_ESTEID_2015)),
            CertificateValidator::buildTrustAnchorsFromCertificates(array(Certificates::getTestEsteid2018CA(), Certificates::getTestEsteid2015CA()))
        ); // ,
            // CertificateValidator::buildCertStoreFromCertificates(TRUSTED_CA_CERTIFICATES));
    }
}
