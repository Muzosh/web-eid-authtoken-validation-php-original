<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use DateInterval;
use DateTime;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateRevokedException;
use muzosh\web_eid_authtoken_validation_php\ocsp\BasicResponseObject;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;
use phpseclib3\File\X509;

final class OcspResponseValidator
{
    /**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9.
     */
    private const OCSP_SIGNING = 'id-kp-OCSPSigning';

    // 15 mins = 900 000 ms
    private const ALLOWED_TIME_SKEW_SECONDS = 900;

    private function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function validateHasSigningExtension(X509 $certificate): void
    {
        if (!$certificate->getExtension('id-ce-extKeyUsage') || !in_array(self::OCSP_SIGNING, $certificate->getExtension('id-ce-extKeyUsage'))) {
            throw new OCSPCertificateException('Certificate '.$certificate->getSubjectDN(X509::DN_STRING).
                ' does not contain the key usage extension for OCSP response signing');
        }
    }

    public static function validateResponseSignature(BasicResponseObject $basicResponse, X509 $responderCert): void
    {
        $publicKey = $responderCert->getPublicKey()->withHash($basicResponse->getSignatureAlgorithm());

        $encodedTbsResponseData = $basicResponse->getEncodedResponseData();
        $signature = $basicResponse->getSignature();
        $result = $publicKey->verify($encodedTbsResponseData, $signature);

        if (!$result) {
            throw new UserCertificateOCSPCheckFailedException('OCSP response signature is invalid');
        }
    }

    public static function validateCertificateStatusUpdateTime(array $certStatusResponse, DateTime $producedAt): void
    {
        // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
        // 4.2.2.  Notes on OCSP Responses
        // 4.2.2.1.  Time
        //   Responses whose nextUpdate value is earlier than
        //   the local system time value SHOULD be considered unreliable.
        //   Responses whose thisUpdate time is later than the local system time
        //   SHOULD be considered unreliable.
        //   If nextUpdate is not set, the responder is indicating that newer
        //   revocation information is available all the time.
        $notAllowedBefore = (clone $producedAt)->sub(new DateInterval('PT'.self::ALLOWED_TIME_SKEW_SECONDS.'S'));
        $notAllowedAfter = (clone $producedAt)->add(new DateInterval('PT'.self::ALLOWED_TIME_SKEW_SECONDS.'S'));

        $thisUpdate = new DateTime($certStatusResponse['thisUpdate']);
        $nextUpdate = isset($certStatusResponse['nextUpdate']) ? new DateTime($certStatusResponse['nextUpdate']) : null;

        if ($notAllowedAfter < $thisUpdate
            || $notAllowedBefore > (!is_null($nextUpdate) ? $nextUpdate : $thisUpdate)) {
            throw new UserCertificateOCSPCheckFailedException('Certificate status update time check failed: '.
                'notAllowedBefore: '.DateAndTime::toUtcString($notAllowedBefore).
                ', notAllowedAfter: '.DateAndTime::toUtcString($notAllowedAfter).
                ', thisUpdate: '.DateAndTime::toUtcString($thisUpdate).
                ', nextUpdate: '.DateAndTime::toUtcString($nextUpdate));
        }
    }

    public static function validateSubjectCertificateStatus(array $certStatusResponse): void
    {
        if (isset($certStatusResponse['certStatus']['good'])) {
            return;
        }
        if (isset($certStatusResponse['certStatus']['revoked'])) {
            $revokedStatus = $certStatusResponse['certStatus']['revoked'];

            throw (isset($revokedStatus['revokedReason']) ?
                new UserCertificateRevokedException('Revocation reason: '.$revokedStatus['revokedReason']) :
                new UserCertificateRevokedException());
        }
        if (isset($certStatusResponse['certStatus']['unknown'])) {
            throw new UserCertificateRevokedException('Unknown status');
        }

        throw new UserCertificateRevokedException('Status is neither good, revoked nor unknown');
    }
}
