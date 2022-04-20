<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;

final class OcspUrl
{
    public const AIA_ESTEID_2015_URL = 'http://aia.sk.ee/esteid2015';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * Returns the OCSP responder URI or null if it doesn't have one.
     */
    public static function getOcspUri(X509 $certificate): ?Uri
    {
        $authorityInformationAccess = $certificate->getExtension('id-pe-authorityInfoAccess');

        if ($authorityInformationAccess) {
            foreach ($authorityInformationAccess as $accessDescription) {
                if ('id-ad-ocsp' === $accessDescription['accessMethod'] && array_key_exists('uniformResourceIdentifier', $accessDescription['accessLocation'])) {
                    $accessLocationUrl = $accessDescription['accessLocation']['uniformResourceIdentifier'];

                    try {
                        return new Uri($accessLocationUrl);
                    } catch (MalformedUriException $e) {
                        throw new MalformedUriException("OCSP Uri from certificate '".$certificate->getSubjectDN(X509::DN_STRING)."' is invalid", -1, $e);
                    }
                }
            }
        }

        return null;
    }
}
