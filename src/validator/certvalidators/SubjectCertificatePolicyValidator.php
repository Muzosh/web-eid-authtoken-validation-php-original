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

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use phpseclib3\File\X509;

final class SubjectCertificatePolicyValidator implements SubjectCertificateValidator
{
    private array $disallowedSubjectCertificatePolicyIds;
	private Logger $logger;

    public function __construct(array $disallowedSubjectCertificatePolicyIds)
    {
        $this->disallowedSubjectCertificatePolicyIds = $disallowedSubjectCertificatePolicyIds;
		$this->logger = WebEidLogger::getLogger(self::class);
    }

    /**
     * Validates that all policies are NOT in disallowedSubjectCertificatePolicyIds.
     *
     * @throws UserCertificateDisallowedPolicyException
     */
    public function validate(X509 $subjectCertificate): void
    {
        $policiesArray = $subjectCertificate->getExtension('id-ce-certificatePolicies');

        // check if all policies are NOT in disallowedSubjectCertificatePolicyIds
        foreach ($policiesArray as $policy) {
            if (in_array($policy['policyIdentifier'], $this->disallowedSubjectCertificatePolicyIds, true)) {
                throw new UserCertificateDisallowedPolicyException();
            }
        }

		$this->logger->debug("User certificate does not contain disallowed policies.");
    }
}
