<?php

/* The MIT License (MIT)
*
* Copyright (c) 2022 Petr Muzikant <pmuzikant@email.cz>
*
* > Permission is hereby granted, free of charge, to any person obtaining a copy
* > of this software and associated documentation files (the "Software"), to deal
* > in the Software without restriction, including without limitation the rights
* > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* > copies of the Software, and to permit persons to whom the Software is
* > furnished to do so, subject to the following conditions:
* >
* > The above copyright notice and this permission notice shall be included in
* > all copies or substantial portions of the Software.
* >
* > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* > THE SOFTWARE.
*/

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
            CertificateValidator::buildTrustedCertificates(array(Certificates::getTestEsteid2018CA(), Certificates::getTestEsteid2018CAGov(), Certificates::getTestEsteid2015CA()))
        );
    }
}
