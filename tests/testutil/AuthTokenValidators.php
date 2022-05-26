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
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use muzosh\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use muzosh\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;
use phpseclib3\File\X509;

final class AuthTokenValidators
{
    private const TOKEN_ORIGIN_URL = 'https://ria.ee';
    private const EST_IDEMIA_POLICY = '1.3.6.1.4.1.51361.1.2.1';

    public static function getAuthTokenValidator(string $url = self::TOKEN_ORIGIN_URL, X509 ...$certificates): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder($url, empty($certificates) ? self::getCACertificates() : $certificates))
            // Assure that all builder methods are covered with tests.
            ->withOcspRequestTimeout(1)
            ->withNonceDisabledOcspUrls(new Uri('http://example.org'))
            ->withoutUserCertificateRevocationCheckWithOcsp()
            ->build()
        ;
    }

    public static function getAuthTokenValidatorWithOcspCheck(): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))->build();
    }

    public static function getAuthTokenValidatorWithDesignatedOcspCheck(): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))->withDesignatedOcspServiceConfiguration(OcspServiceMaker::getDesignatedOcspServiceConfiguration())->build();
    }

    public static function getAuthTokenValidatorWithWrongTrustedCA(): AuthTokenValidator
    {
        return self::getAuthTokenValidator(
            self::TOKEN_ORIGIN_URL,
            ...CertificateLoader::loadCertificatesFromPath(__DIR__.'/../_resources', 'ESTEID2018.cer')
        );
    }

    public static function getAuthTokenValidatorWithDisallowedESTEIDPolicy(): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))->withDisallowedCertificatePolicyIds(self::EST_IDEMIA_POLICY)->withoutUserCertificateRevocationCheckWithOcsp()->build();
    }

    private static function getAuthTokenValidatorBuilder(string $uri, array $certificates): AuthTokenValidatorBuilder
    {
        return (new AuthTokenValidatorBuilder())
            ->withSiteOrigin(new Uri($uri))
            ->withTrustedCertificateAuthorities(...$certificates)
        ;
    }

    private static function getCACertificates(): array
    {
        return CertificateLoader::loadCertificatesFromPath(__DIR__.'/../_resources', 'TEST_of_ESTEID2018.cer');
    }
}
