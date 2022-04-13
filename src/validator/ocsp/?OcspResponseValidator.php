<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

final class OcspResponseValidator {

    /**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9
     */
    private static final const OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    private static final const ALLOWED_TIME_SKEW = TimeUnit.MINUTES.toMillis(15);

    public static void validateHasSigningExtension(X509Certificate certificate) throws OCSPCertificateException {
        Objects.requireNonNull(certificate, "certificate");
        try {
            if (certificate.getExtendedKeyUsage() == null || !certificate.getExtendedKeyUsage().contains(OID_OCSP_SIGNING)) {
                throw new OCSPCertificateException("Certificate " + certificate.getSubjectDN() +
                    " does not contain the key usage extension for OCSP response signing");
            }
        } catch (CertificateParsingException e) {
            throw new OCSPCertificateException("Certificate parsing failed:", e);
        }
    }

    public static void validateResponseSignature(BasicOCSPResp basicResponse, X509CertificateHolder responderCert) throws CertificateException, OperatorCreationException, OCSPException, UserCertificateOCSPCheckFailedException {
        final ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(responderCert);
        if (!basicResponse.isSignatureValid(verifierProvider)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response signature is invalid");
        }
    }

    public static void validateCertificateStatusUpdateTime(SingleResp certStatusResponse, Date producedAt) throws UserCertificateOCSPCheckFailedException {
        // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
        // 4.2.2.  Notes on OCSP Responses
        // 4.2.2.1.  Time
        //   Responses whose nextUpdate value is earlier than
        //   the local system time value SHOULD be considered unreliable.
        //   Responses whose thisUpdate time is later than the local system time
        //   SHOULD be considered unreliable.
        //   If nextUpdate is not set, the responder is indicating that newer
        //   revocation information is available all the time.
        final Date notAllowedBefore = new Date(producedAt.getTime() - ALLOWED_TIME_SKEW);
        final Date notAllowedAfter = new Date(producedAt.getTime() + ALLOWED_TIME_SKEW);
        if (notAllowedAfter.before(certStatusResponse.getThisUpdate()) ||
            notAllowedBefore.after(certStatusResponse.getNextUpdate() != null ?
                certStatusResponse.getNextUpdate() :
                certStatusResponse.getThisUpdate())) {
            throw new UserCertificateOCSPCheckFailedException("Certificate status update time check failed: " +
                "notAllowedBefore: " + toUtcString(notAllowedBefore) +
                ", notAllowedAfter: " + toUtcString(notAllowedAfter) +
                ", thisUpdate: " + toUtcString(certStatusResponse.getThisUpdate()) +
                ", nextUpdate: " + toUtcString(certStatusResponse.getNextUpdate()));
        }
    }

    public static void validateSubjectCertificateStatus(SingleResp certStatusResponse) throws UserCertificateRevokedException {
        final CertificateStatus status = certStatusResponse.getCertStatus();
        if (status == null) {
            return;
        }
        if (status instanceof RevokedStatus) {
            RevokedStatus revokedStatus = (RevokedStatus) status;
            throw (revokedStatus.hasRevocationReason() ?
                new UserCertificateRevokedException("Revocation reason: " + revokedStatus.getRevocationReason()) :
                new UserCertificateRevokedException());
        } else if (status instanceof UnknownStatus) {
            throw new UserCertificateRevokedException("Unknown status");
        } else {
            throw new UserCertificateRevokedException("Status is neither good, revoked nor unknown");
        }
    }

    private static String toUtcString(Date date) {
        if (date == null) {
            return String.valueOf((Object) null);
        }
        final SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        dateFormatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormatter.format(date);
    }

    private OcspResponseValidator() {
        throw new IllegalStateException("Utility class");
    }
}
