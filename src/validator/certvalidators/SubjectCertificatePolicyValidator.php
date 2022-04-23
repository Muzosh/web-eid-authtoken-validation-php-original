<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;
use phpseclib3\File\X509;

final class SubjectCertificatePolicyValidator implements SubjectCertificateValidator
{
    private array $disallowedSubjectCertificatePolicyIds;

    public function __construct(array $disallowedSubjectCertificatePolicyIds)
    {
        $this->disallowedSubjectCertificatePolicyIds = $disallowedSubjectCertificatePolicyIds;
    }

    public function validate(X509 $subjectCertificate): void
    {
        $policiesArray = $subjectCertificate->getExtension('id-ce-certificatePolicies');

        foreach ($policiesArray as $policy) {
            if (in_array($policy['policyIdentifier'], $this->disallowedSubjectCertificatePolicyIds, true)) {
                throw new UserCertificateDisallowedPolicyException();
            }
        }
    }
}
