<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

final class SubjectCertificateNotRevokedValidator {
	private static $logger;
    //private static final DigestCalculator DIGEST_CALCULATOR = Digester.sha1();

    private $trustValidator;
    private $ocspClient;
    private $ocspServiceProvider;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SubjectCertificateNotRevokedValidator(SubjectCertificateTrustedValidator trustValidator,
                                                 OcspClient ocspClient,
                                                 OcspServiceProvider ocspServiceProvider) {
        this.trustValidator = trustValidator;
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when user certificate is revoked or revocation check fails.
     */
    public void validateCertificateNotRevoked(X509Certificate subjectCertificate) throws AuthTokenException {
        try {
            OcspService ocspService = ocspServiceProvider.getService(subjectCertificate);

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            final CertificateID certificateId = getCertificateId(subjectCertificate,
                Objects.requireNonNull(trustValidator.getSubjectCertificateIssuerCertificate()));

            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            LOG.debug("Sending OCSP request");
            final OCSPResp response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request));
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateOCSPCheckFailedException("Response status: " + ocspStatusToString(response.getStatus()));
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            verifyOcspResponse(basicResponse, ocspService, certificateId);
            if (ocspService.doesSupportNonce()) {
                checkNonce(request, basicResponse);
            }
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            throw new UserCertificateOCSPCheckFailedException(e);
        }
    }

    private void verifyOcspResponse(BasicOCSPResp basicResponse, OcspService ocspService, CertificateID requestCertificateId) throws AuthTokenException, OCSPException, CertificateException, OperatorCreationException {
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

    private static void checkNonce(OCSPReq request, BasicOCSPResp response) throws UserCertificateOCSPCheckFailedException {
        final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        final Extension responseNonce = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (!requestNonce.equals(responseNonce)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request and response nonces differ, " +
                "possible replay attack");
        }
    }

    private static CertificateID getCertificateId(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws CertificateEncodingException, IOException, OCSPException {
        final BigInteger serial = subjectCertificate.getSerialNumber();
        return new CertificateID(DIGEST_CALCULATOR,
            new X509CertificateHolder(issuerCertificate.getEncoded()), serial);
    }

    private static String ocspStatusToString(int status) {
        switch (status) {
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
