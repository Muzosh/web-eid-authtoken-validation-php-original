<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;

final class OcspResponseValidator {

    /**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9
     */
    private static const OCSP_SIGNING = "id-kp-OCSPSigning";

	// 15 mins = 900 000 ms
    private static final const ALLOWED_TIME_SKEW_SECONDS = 900;

    public static function validateHasSigningExtension(X509 $certificate):void {
		if (!$certificate->getExtension('id-ce-extKeyUsage') || !in_array(OcspResponseValidator::OCSP_SIGNING,$certificate->getExtension('id-ce-extKeyUsage'))) {
			throw new OCSPCertificateException("Certificate " . $certificate->getSubjectDN(X509::DN_STRING) .
				" does not contain the key usage extension for OCSP response signing");
		}
    }

    public static function validateResponseSignature(BasicOCSPResp $basicResponse, X509CertificateHolder $responderCert) :void {
        final ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(responderCert);
        if (!basicResponse.isSignatureValid(verifierProvider)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response signature is invalid");
        }
    }

    public static function  validateCertificateStatusUpdateTime(SingleResp $certStatusResponse, DateTime $producedAt) : void {
        // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
        // 4.2.2.  Notes on OCSP Responses
        // 4.2.2.1.  Time
        //   Responses whose nextUpdate value is earlier than
        //   the local system time value SHOULD be considered unreliable.
        //   Responses whose thisUpdate time is later than the local system time
        //   SHOULD be considered unreliable.
        //   If nextUpdate is not set, the responder is indicating that newer
        //   revocation information is available all the time.
        $notAllowedBefore = (clone $producedAt)->sub(new DateInterval('PT'.OcspResponseValidator::ALLOWED_TIME_SKEW_SECONDS.'S'));
        $notAllowedAfter = (clone $producedAt)->add(new DateInterval('PT'.OcspResponseValidator::ALLOWED_TIME_SKEW_SECONDS.'S'));
        if ($notAllowedAfter < certStatusResponse.getThisUpdate() ||
            $notAllowedBefore > !is_null(certStatusResponse.getNextUpdate()) ?
                certStatusResponse.getNextUpdate() :
                certStatusResponse.getThisUpdate()) {
            throw new UserCertificateOCSPCheckFailedException("Certificate status update time check failed: " .
                "notAllowedBefore: " . toUtcString(notAllowedBefore) .
                ", notAllowedAfter: " . toUtcString(notAllowedAfter) .
                ", thisUpdate: " . toUtcString(certStatusResponse.getThisUpdate()) .
                ", nextUpdate: " . toUtcString(certStatusResponse.getNextUpdate()));
        }
    }

    public static function validateSubjectCertificateStatus(SingleResp $certStatusResponse):void {
        $status = certStatusResponse.getCertStatus();
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

    private static function toUtcString(DateTime $date):string {;
		return ((clone $date)->setTimezone(new DateTimeZone("UTC")))->format("Y-m-d H:i:s e");
    }

    private function __construct() {
        throw new BadFunctionCallException("Utility class");
    }
}
