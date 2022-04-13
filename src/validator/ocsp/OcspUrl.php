<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use phpseclib3\File\X509;

final class OcspUrl
{
    public const AIA_ESTEID_2015 = 'http://aia.sk.ee/esteid2015';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * Returns the OCSP responder {@link URI} or {@code null} if it doesn't have one.
     */
    public static function getOcspUri(X509 $certificate): array
    {
        $authorityInformationAccess = $certificate->getExtension('id-pe-authorityInfoAccess');
        foreach ($authorityInformationAccess as $accessDescription) {
            if ('id-ad-ocsp' === $accessDescription['accessMethod'] && array_key_exists('uniformResourceIdentifier', $accessDescription['accessLocation'])) {
                $accessLocationUrl = $accessDescription['accessLocation']['uniformResourceIdentifier'];

                return parse_url($accessLocationUrl);
            }
        }
    }
}
