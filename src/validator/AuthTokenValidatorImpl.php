<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\util\CertStore;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateExpiryValidator;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateNotRevokedValidator;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePolicyValidator;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePurposeValidator;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateTrustedValidator;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use phpseclib3\File\X509;
use Throwable;

/**
 * Provides the default implementation of AuthTokenValidator.
 */
final class AuthTokenValidatorImpl implements AuthTokenValidator
{
    private const TOKEN_MIN_LENGTH = 100;
    private const TOKEN_MAX_LENGTH = 10000;

    private Logger $logger;
    private AuthTokenValidationConfiguration $configuration;
    private SubjectCertificateValidatorBatch $subjectCertificateValidators;
    private TrustedAnchors $trustedCACertificateAnchors;

    // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
    // private CertStore $trustedCACertificateCertStore;

    // OcspClient uses OkHttp internally.
    // OkHttp performs best when a single OkHttpClient instance is created and reused for all HTTP calls.
    // This is because each client holds its own connection pool and thread pools.
    // Reusing connections and threads reduces latency and saves memory.
    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;
    private AuthTokenSignatureValidator $authTokenSignatureValidator;

    public function __construct(AuthTokenValidationConfiguration $configuration)
    {
        $this->logger = WebEidLogger::getLogger(AuthTokenValidatorImpl::class);

        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        $this->configuration = clone $configuration;

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        $this->trustedCACertificateAnchors = CertificateValidator::buildTrustAnchorsFromCertificates($configuration->getTrustedCACertificates());

        // CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
        // $this->trustedCACertificateCertStore = CertificateValidator::buildCertStoreFromCertificates($configuration->getTrustedCACertificates());

        $this->subjectCertificateValidators = new SubjectCertificateValidatorBatch(
            new SubjectCertificateExpiryValidator($this->trustedCACertificateAnchors),
            new SubjectCertificatePurposeValidator(),
            new SubjectCertificatePolicyValidator($configuration->getDisallowedSubjectCertificatePolicyIds())
        );

        if ($configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $this->ocspClient = OcspClientImpl::build($configuration->getOcspRequestTimeoutSeconds());
            $this->ocspServiceProvider = new OcspServiceProvider(
                $configuration->getDesignatedOcspServiceConfiguration(),
                new AiaOcspServiceConfiguration(
                    $configuration->getNonceDisabledOcspUrls(),
                    $this->trustedCACertificateAnchors,
                    $this->trustedCACertificateCertStore
                )
            );
        }

        $this->authTokenSignatureValidator = new AuthTokenSignatureValidator($configuration->getSiteOrigin());
    }

    public function parse(string $authToken): WebEidAuthToken
    {
        $this->logger->info('Starting token parsing');

        try {
            $this->validateTokenLength($authToken);

            return $this->parseToken($authToken);
        } catch (Throwable $e) {
            $this->logger->warning('Token parsing was interrupted: '.print_r($e));

            throw $e;
        }
    }

    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509
    {
        $this->logger->info('Starting token validation');

        try {
            return $this->validateToken($authToken, $currentChallengeNonce);
        } catch (Throwable $e) {
            $this->logger->warning('Token validation was interrupted: '.print_r($e));

            throw $e;
        }
    }

    private function validateTokenLength(string $authToken): void
    {
        if (is_null($authToken) || strlen($authToken) < AuthTokenValidatorImpl::TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException('Auth token is null or too short');
        }
        if (strlen($authToken) > AuthTokenValidatorImpl::TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException('Auth token is too long');
        }
    }

    private function parseToken(string $authToken): WebEidAuthToken
    {
        return new WebEidAuthToken($authToken);
    }

    private function validateToken(WebEidAuthToken $token, string $currentChallengeNonce): X509
    {
        if (is_null($token->getFormat()) || 0 !== strpos($token->getFormat(), AuthTokenValidator::CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '".AuthTokenValidator::CURRENT_TOKEN_FORMAT_VERSION."' is currently supported");
        }
        $unverifiedCertificate = $token->getUnverifiedCertificate();

        if (is_null($unverifiedCertificate) || empty($unverifiedCertificate)) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        $subjectCertificate = new X509($unverifiedCertificate);

        $this->subjectCertificateValidators->executeFor($subjectCertificate);
        $this->getCertTrustValidators()->executeFor($subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin, challenge
        // and, if part of the signature, origin certificate have been implicitly and correctly verified
        // without the need to implement any additional checks.
        $this->authTokenSignatureValidator->validate(
            $token->getAlgorithm(),
            $token->getSignature(),
            $subjectCertificate->getPublicKey(),
            $currentChallengeNonce
        );

        return $subjectCertificate;
    }

    /**
     * Creates the certificate trust validators batch.
     * As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
     * they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence, they are
     * re-created for each validation run for thread safety.
     *
     * @return certificate trust validator batch
     */
    private function getCertTrustValidators(): SubjectCertificateValidatorBatch
    {
        $certTrustedValidator =
            new SubjectCertificateTrustedValidator(
                $this->trustedCACertificateAnchors,
                // $this->trustedCACertificateCertStore
            );

        $validatorBatch = new SubjectCertificateValidatorBatch(
            $certTrustedValidator
        );

        $validatorBatch->addOptional(
            $this->configuration->isUserCertificateRevocationCheckWithOcspEnabled(),
            new SubjectCertificateNotRevokedValidator($certTrustedValidator, $this->ocspClient, $this->ocspServiceProvider)
        );

        return $validatorBatch;
    }
}
