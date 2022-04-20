<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateMissingPurposeException;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateWrongPurposeException;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificatePurposeValidator implements SubjectCertificateValidator
{
    private const EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = 'id-kp-clientAuth';

    /**
     * Validates that the purpose of the user certificate from the authentication token contains client authentication.
     *
     * @param subjectCertificate user certificate to be validated
     */
    public function validate(X509 $subjectCertificate): void
    {
        $usages = $subjectCertificate->getExtension('id-ce-extKeyUsage');
        if (!$usages || empty($usages)) {
            throw new UserCertificateMissingPurposeException();
        }
        if (!in_array(SubjectCertificatePurposeValidator::EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION, $usages)) {
            throw new UserCertificateWrongPurposeException();
        }
        WebEidLogger::getLogger(SubjectCertificatePurposeValidator::class)->debug('User certificate can be used for client authentication.');
    }
}
