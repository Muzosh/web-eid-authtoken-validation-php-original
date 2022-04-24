<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\ocsp\BasicResponseObject;
use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspOCSPResponseStatus;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspRequestObject;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspUtil;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspRequestBuilder;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\service\OcspService;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\X509;

final class SubjectCertificateNotRevokedValidator implements SubjectCertificateValidator
{
    private static $logger;

    private SubjectCertificateTrustedValidator $trustValidator;
    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;

    public function __construct(
        SubjectCertificateTrustedValidator $trustValidator,
        OcspClient $ocspClient,
        OcspServiceProvider $ocspServiceProvider
    ) {
        $this->logger = WebEidLogger::getLogger(self::class);
        $this->trustValidator = $trustValidator;
        $this->ocspClient = $ocspClient;
        $this->ocspServiceProvider = $ocspServiceProvider;
    }

    public function validate(X509 $subjectCertificate): void
    {
        $ocspService = $this->ocspServiceProvider->getService($subjectCertificate);

        if (!$ocspService->doesSupportNonce()) {
            $this->logger->debug('Disabling OCSP nonce extension');
        }

        $certificateId = OcspUtil::getCertificateId($subjectCertificate, $this->trustValidator->getSubjectCertificateIssuerCertificate());

        $request = (new OcspRequestBuilder())
            ->withCertificateId($certificateId)
            ->enableOcspNonce($ocspService->doesSupportNonce())
            ->build()
        ;

        $this->logger->debug('Sending OCSP request');
        $response = $this->ocspClient->request($ocspService->getAccessLocation(), $request->getEncodedDER());
        if ($response->getStatus() != OcspOCSPResponseStatus::MAP['mapping'][0]) {
            throw new UserCertificateOCSPCheckFailedException('Response status: '.$response->getStatus());
        }

        $basicResponse = $response->getBasicResponse();
        $this->verifyOcspResponse($basicResponse, $ocspService, $certificateId);
        if ($ocspService->doesSupportNonce()) {
            $this->checkNonce($request, $basicResponse);
        }
    }

    private function verifyOcspResponse(BasicResponseObject $basicResponse, OcspService $ocspService, array $requestCertificateId): void
    {
        // The verification algorithm follows RFC 2560, https://www.ietf.org/rfc/rfc2560.txt.
        //
        // 3.2.  Signed Response Acceptance Requirements
        //   Prior to accepting a signed response for a particular certificate as
        //   valid, OCSP clients SHALL confirm that:
        //
        //   1. The certificate identified in a received response corresponds to
        //      the certificate that was identified in the corresponding request.

        // As we sent the request for only a single certificate, we expect only a single response.
        if (1 != count($basicResponse->getResponses())) {
            throw new UserCertificateOCSPCheckFailedException('OCSP response must contain one response, received '.count($basicResponse->getResponses()).' responses instead.');
        }

        $certStatusResponse = $basicResponse->getResponses()[0];
        if ($requestCertificateId != $certStatusResponse['certID']) {
            throw new UserCertificateOCSPCheckFailedException('OCSP responded with certificate ID that differs from the requested ID');
        }

        //   2. The signature on the response is valid.

        // We assume that the responder includes its certificate in the certs field of the response
        // that helps us to verify it. According to RFC 2560 this field is optional, but including it
        // is standard practice.
        if (1 != count($basicResponse->getCerts())) {
            throw new UserCertificateOCSPCheckFailedException('OCSP response must contain one responder certificate, received '.count($basicResponse->getCerts()).' certificates instead');
        }

        // we need to re-encode certificate array as there exists some
        // more loading in X509->loadX509 method, which are not public if loading from array
        // for example without this the publicKey would not be in PEM format
        // and X509->getPublicKey() will throw error
        $responderCert = new X509();
        $responderCert->loadX509($basicResponse->getCerts()[0]);

        OcspResponseValidator::validateResponseSignature($basicResponse, $responderCert);

        //   3. The identity of the signer matches the intended recipient of the
        //      request.
        //
        //   4. The signer is currently authorized to provide a response for the
        //      certificate in question.

        $producedAt = $basicResponse->getProducedAt();
        $ocspService->validateResponderCertificate($responderCert, $producedAt);

        //   5. The time at which the status being indicated is known to be
        //      correct (thisUpdate) is sufficiently recent.
        //
        //   6. When available, the time at or before which newer information will
        //      be available about the status of the certificate (nextUpdate) is
        //      greater than the current time.

        OcspResponseValidator::validateCertificateStatusUpdateTime($certStatusResponse, $producedAt);

        // Now we can accept the signed response as valid and validate the certificate status.
        OcspResponseValidator::validateSubjectCertificateStatus($certStatusResponse);
        $this->logger->debug('OCSP check result is GOOD');
    }

    private static function checkNonce(OcspRequestObject $request, BasicResponseObject $response): void
    {
        $requestNonce = $request->getNonceExtension();
        $responseNonce = $response->getNonceExtension();
        if ($requestNonce !== $responseNonce) {
            throw new UserCertificateOCSPCheckFailedException('OCSP request and response nonces differ, possible replay attack');
        }
    }
}
