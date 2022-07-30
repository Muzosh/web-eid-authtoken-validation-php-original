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

use ArithmeticError;
use DivisionByZeroError;
use InvalidArgumentException as GlobalInvalidArgumentException;
use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenSignatureValidationException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNullOrEmptyException;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
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
use phpseclib3\Exception\InconsistentSetupException;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;
use Psr\Log\InvalidArgumentException;
use RangeException;
use RuntimeException;
use Throwable;
use TypeError;
use UnexpectedValueException;

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
    private TrustedCertificates $trustedCertificates;

    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;
    private AuthTokenSignatureValidator $authTokenSignatureValidator;

    public function __construct(AuthTokenValidationConfiguration $configuration)
    {
        $this->logger = WebEidLogger::getLogger(self::class);

        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        $this->configuration = clone $configuration;

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        $this->trustedCertificates = CertificateValidator::buildTrustedCertificates($configuration->getTrustedCertificates());

        $this->subjectCertificateValidators = new SubjectCertificateValidatorBatch(
            new SubjectCertificateExpiryValidator($this->trustedCertificates),
            new SubjectCertificatePurposeValidator(),
            new SubjectCertificatePolicyValidator($configuration->getDisallowedSubjectCertificatePolicyIds())
        );

        if ($configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $this->ocspClient = OcspClientImpl::build($configuration->getOcspRequestTimeoutSeconds());
            $this->ocspServiceProvider = new OcspServiceProvider(
                $configuration->getDesignatedOcspServiceConfiguration(),
                new AiaOcspServiceConfiguration(
                    $configuration->getNonceDisabledOcspUrls(),
                    $this->trustedCertificates
                )
            );
        }

        $this->authTokenSignatureValidator = new AuthTokenSignatureValidator($configuration->getSiteOrigin());
    }

    /**
     * @throws InvalidArgumentException
     * @throws Throwable
     */
    public function parse(string $authToken): WebEidAuthToken
    {
        $this->logger->info('Starting token parsing');

        try {
            $this->validateTokenLength($authToken);

            return $this->parseToken($authToken);
        } catch (Throwable $e) {
            $this->logger->warning('Token parsing was interrupted: '.strval($e));

            throw $e;
        }
    }

    /**
     * @throws InvalidArgumentException
     * @throws Throwable
     */
    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509
    {
        $this->logger->info('Starting token validation');

        try {
            return $this->validateToken($authToken, $currentChallengeNonce);
        } catch (Throwable $e) {
            $this->logger->warning('Token validation was interrupted: '.strval($e));

            throw $e;
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateTokenLength(string $authToken): void
    {
        if (is_null($authToken) || strlen($authToken) < self::TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException('Auth token is null or too short');
        }
        if (strlen($authToken) > self::TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException('Auth token is too long');
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function parseToken(string $authToken): WebEidAuthToken
    {
        try {
            $token = new WebEidAuthToken($authToken);
            if (is_null($token)) {
                throw new AuthTokenParseException('Web eID authentication token is null');
            }

            return $token;
        } catch (UnexpectedValueException $e) {
            throw new AuthTokenParseException('Error parsing Web eID authentication token', $e);
        }
    }

    /**
     * @throws AuthTokenParseException
     * @throws RangeException
     * @throws TypeError
     * @throws RuntimeException
     * @throws CertificateDecodingException
     * @throws NoKeyLoadedException
     * @throws InconsistentSetupException
     * @throws GlobalInvalidArgumentException
     * @throws ChallengeNullOrEmptyException
     * @throws DivisionByZeroError
     * @throws ArithmeticError
     * @throws AuthTokenSignatureValidationException
     */
    private function validateToken(WebEidAuthToken $token, string $currentChallengeNonce): X509
    {
        if (is_null($token->getFormat()) || 0 !== strpos($token->getFormat(), self::CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '".self::CURRENT_TOKEN_FORMAT_VERSION."' is currently supported");
        }
        $unverifiedCertificate = $token->getUnverifiedCertificate();

        if (is_null($unverifiedCertificate) || empty($unverifiedCertificate)) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        $subjectCertificate = new X509();
        $result = $subjectCertificate->loadX509($unverifiedCertificate);

        if (!$result) {
            throw new CertificateDecodingException('Could not decode certificate: '.$unverifiedCertificate);
        }

        $this->subjectCertificateValidators->executeFor($subjectCertificate);
        $this->getCertTrustValidators()->executeFor($subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin and challenge
        // have been implicitly and correctly verified without the need to implement any additional checks.
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
     * @return SubjectCertificateValidatorBatch certificate trust validator batch
     */
    private function getCertTrustValidators(): SubjectCertificateValidatorBatch
    {
        $certTrustedValidator =
            new SubjectCertificateTrustedValidator(
                $this->trustedCertificates,
            );

        $validatorBatch = new SubjectCertificateValidatorBatch(
            $certTrustedValidator
        );

        // this if needs to be here because PHP does not like using uninitialized ocspClient and
        // ocspServiceProvider even if it is not used because of condition in addOptional
        if ($this->configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $validatorBatch->addOptional(
                $this->configuration->isUserCertificateRevocationCheckWithOcspEnabled(),
                new SubjectCertificateNotRevokedValidator($certTrustedValidator, $this->ocspClient, $this->ocspServiceProvider)
            );
        }

        return $validatorBatch;
    }
}
