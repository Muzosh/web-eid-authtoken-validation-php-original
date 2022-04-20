<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;

final class SubjectCertificateNotRevokedValidator implements SubjectCertificateValidator{
	private static $logger;
    //private static final DigestCalculator DIGEST_CALCULATOR = Digester.sha1();

    private $trustValidator;
    private $ocspClient;
    private $ocspServiceProvider;

    public function __construct(SubjectCertificateTrustedValidator $trustValidator,
									OcspClient $ocspClient,
                                                 OcspServiceProvider $ocspServiceProvider) {
		$this->logger = WebEidLogger::getLogger(SubjectCertificateNotRevokedValidator::class);
        $this->trustValidator = $trustValidator;
        $this->ocspClient = $ocspClient;
        $this->ocspServiceProvider = $ocspServiceProvider;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when user certificate is revoked or revocation check fails.
     */
    public function validate(X509 $subjectCertificate): void {
        $ocspService = $this->ocspServiceProvider->getService($subjectCertificate);

		if (!$ocspService->doesSupportNonce()) {
			$this->logger->debug("Disabling OCSP nonce extension");
		}

		$certificateId = getCertificateId($subjectCertificate, $trustValidator->getSubjectCertificateIssuerCertificate());

		$request = new OcspRequestBuilder()
			.withCertificateId(certificateId)
			.enableOcspNonce($ocspService->doesSupportNonce())
			.build();

		$this->logger->debug("Sending OCSP request");
		$response = $ocspClient.request(ocspService.getAccessLocation(), request);
		if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
			throw new UserCertificateOCSPCheckFailedException("Response status: " + ocspStatusToString(response.getStatus()));
		}

		$basicResponse = (BasicOCSPResp) response.getResponseObject();
		verifyOcspResponse(basicResponse, ocspService, certificateId);
		if (ocspService.doesSupportNonce()) {
			checkNonce(request, basicResponse);
		}
    }

    private function verifyOcspResponse(BasicOCSPResp $basicResponse, OcspService $ocspService, CertificateID $requestCertificateId) : void {
        // The verification algorithm follows RFC 2560, https://www.ietf.org/rfc/rfc2560.txt.
        //
        // 3.2.  Signed Response Acceptance Requirements
        //   Prior to accepting a signed response for a particular certificate as
        //   valid, OCSP clients SHALL confirm that:
        //
        //   1. The certificate identified in a received response corresponds to
        //      the certificate that was identified in the corresponding request.

        // As we sent the request for only a single certificate, we expect only a single response.
        if (basicResponse.getResponses().length != 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain one response, "
                + "received " + basicResponse.getResponses().length + " responses instead");
        }
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        if (!requestCertificateId.equals(certStatusResponse.getCertID())) {
            throw new UserCertificateOCSPCheckFailedException("OCSP responded with certificate ID that differs from the requested ID");
        }

        //   2. The signature on the response is valid.

        // We assume that the responder includes its certificate in the certs field of the response
        // that helps us to verify it. According to RFC 2560 this field is optional, but including it
        // is standard practice.
        if (basicResponse.getCerts().length != 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain one responder certificate, "
                + "received " + basicResponse.getCerts().length + " certificates instead");
        }
        final X509CertificateHolder responderCert = basicResponse.getCerts()[0];
        OcspResponseValidator.validateResponseSignature(basicResponse, responderCert);

        //   3. The identity of the signer matches the intended recipient of the
        //      request.
        //
        //   4. The signer is currently authorized to provide a response for the
        //      certificate in question.

        final Date producedAt = basicResponse.getProducedAt();
        ocspService.validateResponderCertificate(responderCert, producedAt);

        //   5. The time at which the status being indicated is known to be
        //      correct (thisUpdate) is sufficiently recent.
        //
        //   6. When available, the time at or before which newer information will
        //      be available about the status of the certificate (nextUpdate) is
        //      greater than the current time.

        OcspResponseValidator.validateCertificateStatusUpdateTime(certStatusResponse, producedAt);

        // Now we can accept the signed response as valid and validate the certificate status.
        OcspResponseValidator.validateSubjectCertificateStatus(certStatusResponse);
        LOG.debug("OCSP check result is GOOD");
    }

    private static function checkNonce(OCSPReq $request, BasicOCSPResp $response): void {
        final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        final Extension responseNonce = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (!requestNonce.equals(responseNonce)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request and response nonces differ, " +
                "possible replay attack");
        }
    }

    private static function getCertificateId(X509 $subjectCertificate, X509 $issuerCertificate) : CertificateID {
        final BigInteger serial = subjectCertificate.getSerialNumber();
        return new CertificateID(DIGEST_CALCULATOR,
            new X509CertificateHolder(issuerCertificate.getEncoded()), serial);
    }

    private static function ocspStatusToString(int $status): string{
        switch ($status) {
            case OCSPResp.MALFORMED_REQUEST:
                return "malformed request";
            case OCSPResp.INTERNAL_ERROR:
                return "internal error";
            case OCSPResp.TRY_LATER:
                return "service unavailable";
            case OCSPResp.SIG_REQUIRED:
                return "request signature missing";
            case OCSPResp.UNAUTHORIZED:
                return "unauthorized";
            default:
                return "unknown";
        }
    }

}
