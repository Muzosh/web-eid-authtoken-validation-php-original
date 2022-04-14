<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;

/**
 * Provides the default implementation of AuthTokenValidator.
 */
final class AuthTokenValidatorImpl implements AuthTokenValidator {

    private const TOKEN_MIN_LENGTH = 100;
    private const TOKEN_MAX_LENGTH = 10000;

    private $logger;
    private $authTokenValidationConfiguration;
    private $subjectCertificateValidators;
    private $trustedCACertificateAnchors;
    private $trustedCACertificateCertStore;

    // OcspClient uses OkHttp internally.
    // OkHttp performs best when a single OkHttpClient instance is created and reused for all HTTP calls.
    // This is because each client holds its own connection pool and thread pools.
    // Reusing connections and threads reduces latency and saves memory.
    private $ocspClient;
    private $ocspServiceProvider;
    private $authTokenSignatureValidator;

    /**
     * @param configuration configuration parameters for the token validator
     */
    public function __construct(AuthTokenValidationConfiguration $configuration) {
		$this->logger = WebEidLogger::getLogger(AuthTokenValidatorImpl::class);

        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        $this->configuration = $configuration;

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        $this->trustedCACertificateAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(configuration.getTrustedCACertificates());
        $this->trustedCACertificateCertStore = CertificateValidator.buildCertStoreFromCertificates(configuration.getTrustedCACertificates());

        $this->subjectCertificateValidators = SubjectCertificateValidatorBatch.createFrom(
            new SubjectCertificateExpiryValidator(trustedCACertificateAnchors)::validateCertificateExpiry,
            SubjectCertificatePurposeValidator::validateCertificatePurpose,
            new SubjectCertificatePolicyValidator(configuration.getDisallowedSubjectCertificatePolicies())::validateCertificatePolicies
        );

        if (configuration.isUserCertificateRevocationCheckWithOcspEnabled()) {
            ocspClient = OcspClientImpl.build(configuration.getOcspRequestTimeout());
            ocspServiceProvider = new OcspServiceProvider(
                configuration.getDesignatedOcspServiceConfiguration(),
                new AiaOcspServiceConfiguration(configuration.getNonceDisabledOcspUrls(),
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore));
        }

        authTokenSignatureValidator = new AuthTokenSignatureValidator(configuration.getSiteOrigin());
    }

    public function parse(string $authToken):WebEidAuthToken {
        try {
            LOG.info("Starting token parsing");
            validateTokenLength(authToken);
            return parseToken(authToken);
        } catch (Exception e) {
            // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
            LOG.warn("Token parsing was interrupted:", e);
            throw e;
        }
    }

    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce):X509{
        try {
            LOG.info("Starting token validation");
            return validateToken(authToken, currentChallengeNonce);
        } catch (Exception e) {
            // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
            LOG.warn("Token validation was interrupted:", e);
            throw e;
        }
    }

    private function validateTokenLength(string $authToken):void {
        if (authToken == null || authToken.length() < TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException("Auth token is null or too short");
        }
        if (authToken.length() > TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException("Auth token is too long");
        }
    }

    private function parseToken(string $authToken) :WebEidAuthToken {
        try {
            final WebEidAuthToken token = objectMapper.readValue(authToken, WebEidAuthToken.class);
            if (token == null) {
                throw new AuthTokenParseException("Web eID authentication token is null");
            }
            return token;
        } catch (IOException e) {
            throw new AuthTokenParseException("Error parsing Web eID authentication token", e);
        }
    }

    private function validateToken(WebEidAuthToken $token, string $currentChallengeNonce):X509 {
        if (token.getFormat() == null || !token.getFormat().startsWith(CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '" + CURRENT_TOKEN_FORMAT_VERSION +
                "' is currently supported");
        }
        if (token.getUnverifiedCertificate() == null || token.getUnverifiedCertificate().isEmpty()) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        final X509 subjectCertificate = CertificateLoader.decodeCertificateFromBase64(token.getUnverifiedCertificate());

        subjectCertificateValidators.executeFor(subjectCertificate);
        getCertTrustValidators().executeFor(subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin, challenge
        // and, if part of the signature, origin certificate have been implicitly and correctly verified
        // without the need to implement any additional checks.
        authTokenSignatureValidator.validate(token.getAlgorithm(),
            token.getSignature(),
            subjectCertificate.getPublicKey(),
            currentChallengeNonce);

        return subjectCertificate;
    }

    /**
     * Creates the certificate trust validators batch.
     * As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
     * they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence, they are
     * re-created for each validation run for thread safety.
     *
     * @return certificate trust validator batch
     */
    private function getCertTrustValidators(): SubjectCertificateValidatorBatch {
        final SubjectCertificateTrustedValidator certTrustedValidator =
            new SubjectCertificateTrustedValidator(trustedCACertificateAnchors, trustedCACertificateCertStore);
        return SubjectCertificateValidatorBatch.createFrom(
            certTrustedValidator::validateCertificateTrusted
        ).addOptional(configuration.isUserCertificateRevocationCheckWithOcspEnabled(),
            new SubjectCertificateNotRevokedValidator(certTrustedValidator, ocspClient, ocspServiceProvider)::validateCertificateNotRevoked
        );
    }

}
