<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

final class SubjectCertificatePolicyValidator {

    private $disallowedSubjectCertificatePolicies;

    public function __construct(array $disallowedSubjectCertificatePolicies) {
        $this->disallowedSubjectCertificatePolicies = $disallowedSubjectCertificatePolicies;
    }

    /**
     * Validates that the user certificate policies match the configured policies.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateDisallowedPolicyException when user certificate policy does not match the configured policies.
     * @throws UserCertificateParseException when user certificate policy is invalid.
     */
    public function validateCertificatePolicies(X509 $subjectCertificate):void {
        $extensionValue = $subjectCertificate->getExtension("id-ce-certificatePolicies");
		
		$policies = CertificatePolicies.getInstance(
			JcaX509ExtensionUtils.parseExtensionValue(extensionValue)
		);
		final Optional<PolicyInformation> disallowedPolicy = Arrays.stream(policies.getPolicyInformation())
			.filter(policyInformation ->
				disallowedSubjectCertificatePolicies.contains(policyInformation.getPolicyIdentifier()))
			.findFirst();
		if (disallowedPolicy.isPresent()) {
			throw new UserCertificateDisallowedPolicyException();
		}
    }
}
