<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use muzosh\web_eid_authtoken_validation_php\util\SubjectCertificateValidatorArray;
use phpseclib3\File\X509;

final class SubjectCertificateValidatorBatch
{
    private SubjectCertificateValidatorArray $validatorList;

    public function __construct(SubjectCertificateValidator ...$validatorList)
    {
        $this->validatorList = new SubjectCertificateValidatorArray(...$validatorList);
    }

    public function executeFor(X509 $subjectCertificate): void
    {
        foreach ($this->validatorList as $validator) {
            $validator->validate($subjectCertificate);
        }
    }

    public function addOptional(bool $condition, SubjectCertificateValidator $optionalValidator): SubjectCertificateValidatorBatch
    {
        if ($condition) {
            $this->validatorList->pushItem($optionalValidator);
        }

        return $this;
    }
}
