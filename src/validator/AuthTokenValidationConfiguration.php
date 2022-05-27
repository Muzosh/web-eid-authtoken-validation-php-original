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

namespace muzosh\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;
use muzosh\web_eid_authtoken_validation_php\util\SubjectCertificatePolicyIds;
use muzosh\web_eid_authtoken_validation_php\util\UriUniqueArray;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;

/**
 * Stores configuration parameters for AuthTokenValidatorImpl.
 */
final class AuthTokenValidationConfiguration
{
    private bool $isUserCertificateRevocationCheckWithOcspEnabled = true;
    private int $ocspRequestTimeoutSeconds = 5;
    private ?Uri $siteOrigin = null;
    private ?DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration = null;

    private array $trustedCertificates = array();
    private array $disallowedSubjectCertificatePolicyIds;
    private UriUniqueArray $nonceDisabledOcspUrls;

    public function __construct()
    {
        // Don't allow Estonian Mobile-ID policy by default.
        $this->disallowedSubjectCertificatePolicyIds = array(
            SubjectCertificatePolicyIds::$ESTEID_SK_2015_MOBILE_ID_POLICY_V1,
            SubjectCertificatePolicyIds::$ESTEID_SK_2015_MOBILE_ID_POLICY_V2,
            SubjectCertificatePolicyIds::$ESTEID_SK_2015_MOBILE_ID_POLICY_V3,
            SubjectCertificatePolicyIds::$ESTEID_SK_2015_MOBILE_ID_POLICY,
        );

        // Disable OCSP nonce extension for EstEID 2015 cards by default.
        $this->nonceDisabledOcspUrls = new UriUniqueArray(new Uri(OcspUrl::AIA_ESTEID_2015_URL));
    }

    public function setSiteOrigin(Uri $siteOrigin): void
    {
        $this->siteOrigin = $siteOrigin;
    }

    public function getSiteOrigin(): ?Uri
    {
        return $this->siteOrigin;
    }

    public function &getTrustedCertificates(): array
    {
        return $this->trustedCertificates;
    }

    public function isUserCertificateRevocationCheckWithOcspEnabled(): bool
    {
        return $this->isUserCertificateRevocationCheckWithOcspEnabled;
    }

    public function setUserCertificateRevocationCheckWithOcspDisabled(): void
    {
        $this->isUserCertificateRevocationCheckWithOcspEnabled = false;
    }

    public function getOcspRequestTimeoutSeconds(): int
    {
        return $this->ocspRequestTimeoutSeconds;
    }

    public function setOcspRequestTimeoutSeconds(int $ocspRequestTimeoutSeconds): void
    {
        $this->ocspRequestTimeoutSeconds = $ocspRequestTimeoutSeconds;
    }

    public function getDesignatedOcspServiceConfiguration(): ?DesignatedOcspServiceConfiguration
    {
        return $this->designatedOcspServiceConfiguration;
    }

    public function setDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration): void
    {
        $this->designatedOcspServiceConfiguration = $designatedOcspServiceConfiguration;
    }

    public function &getDisallowedSubjectCertificatePolicyIds(): array
    {
        return $this->disallowedSubjectCertificatePolicyIds;
    }

    public function getNonceDisabledOcspUrls(): UriUniqueArray
    {
        return $this->nonceDisabledOcspUrls;
    }

    /**
     * Checks that the configuration parameters are valid.
     *
     * @throws NullPointerException     when required parameters are null
     * @throws IllegalArgumentException when any parameter is invalid
     */
    public function validate(): void
    {
        if (is_null($this->siteOrigin)) {
            throw new InvalidArgumentException('Origin URI must not be null');
        }

        self::validateIsOriginURL($this->siteOrigin);

        if (0 == count($this->trustedCertificates)) {
            throw new InvalidArgumentException('At least one trusted certificate authority must be provided');
        }
        DateAndTime::requirePositiveDuration($this->ocspRequestTimeoutSeconds, 'OCSP request timeout');
    }

    /**
     * Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     * in the form of <scheme> "://" <hostname> [ ":" <port> ].
     *
     * @param uri URI with origin URL
     *
     * @throws IllegalArgumentException when the URI is not in the form of origin URL
     */
    public static function validateIsOriginURL(Uri $uri): void
    {
        // 1. Verify that the URI can be converted to absolute URL.
        if (!Uri::isAbsolute($uri)) {
            throw new InvalidArgumentException('Provided URI is not a valid URL');
        }

        // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
        if (!Uri::isSameDocumentReference(
            $uri,
            Uri::fromParts(
                array(
                    'scheme' => 'https',
                    'host' => $uri->getHost(),
                    'port' => $uri->getPort(),
                )
            )
        )) {
            throw new InvalidArgumentException('Origin URI must only contain the HTTPS scheme, host and optional port component');
        }
    }
}
