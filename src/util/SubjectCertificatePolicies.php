<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;

final class SubjectCertificatePolicies
{
    private const ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX = '1.3.6.1.4.1.10015.1.3';

    public static $ESTEID_SK_2015_MOBILE_ID_POLICY = SubjectCertificatePolicies::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX;
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V1 = SubjectCertificatePolicies::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.1';
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V2 = SubjectCertificatePolicies::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.2';
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V3 = SubjectCertificatePolicies::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.3';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }
}
