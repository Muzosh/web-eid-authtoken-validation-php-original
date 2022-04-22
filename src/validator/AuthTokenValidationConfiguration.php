<?php

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
    private Uri $siteOrigin;
    private DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration;

    private array $trustedCACertificates = array();
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

    public function getSiteOrigin(): Uri
    {
        return $this->siteOrigin;
    }

    public function getTrustedCACertificates(): array
    {
        return $this->trustedCACertificates;
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

    public function getDesignatedOcspServiceConfiguration(): DesignatedOcspServiceConfiguration
    {
        return $this->designatedOcspServiceConfiguration;
    }

    public function setDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration): void
    {
        $this->designatedOcspServiceConfiguration = $designatedOcspServiceConfiguration;
    }

    public function getDisallowedSubjectCertificatePolicyIds(): array
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

        AuthTokenValidationConfiguration::validateIsOriginURL($this->siteOrigin);

        if (0 == count($this->trustedCACertificates)) {
            throw new InvalidArgumentException('At least one trusted certificate authority must be provided');
        }
        DateAndTime::requirePositiveDuration($this->ocspRequestTimeoutSeconds, 'OCSP request timeout');
    }

    public function copy(): AuthTokenValidationConfiguration
    {
        return AuthTokenValidationConfiguration::duplicate($this);
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

    // might not be needed since we use 'clone' in PHP
    // private static function duplicate(AuthTokenValidationConfiguration $other)
    // {
    //     $new = new AuthTokenValidationConfiguration();

    //     $new->siteOrigin = clone $other->siteOrigin;
    //     $new->trustedCACertificates = array_unique($other->trustedCACertificates, SORT_REGULAR);
    //     $new->isUserCertificateRevocationCheckWithOcspEnabled = clone $other->isUserCertificateRevocationCheckWithOcspEnabled;
    //     $new->ocspRequestTimeoutSeconds = $other->ocspRequestTimeoutSeconds;
    //     $new->designatedOcspServiceConfiguration = clone $other->designatedOcspServiceConfiguration;
    //     $new->disallowedSubjectCertificatePolicyIds = array_unique($other->disallowedSubjectCertificatePolicyIds, SORT_REGULAR);
    //     $new->nonceDisabledOcspUrls = clone $other->nonceDisabledOcspUrls;

    //     return $new;
    // }
}
