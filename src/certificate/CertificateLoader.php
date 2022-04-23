<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use phpseclib3\File\X509;
use Throwable;

final class CertificateLoader
{
    // TODO: put this into config? maybe use nextpack to create better PHP library skeleton?
    private const CERTPATH = '../../certs/';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function loadCertificatesFromResources(string ...$resourceNames): array
    {
        $caCertificates = array();
        foreach ($resourceNames as $resourceName) {
            $x509 = new X509();
            $result = $x509->loadX509(file_get_contents(CertificateLoader::CERTPATH.$resourceName));
            if ($result) {
                array_push($caCertificates, $x509);
            } else {
                throw new CertificateDecodingException($resourceName);
            }
        }

        return $caCertificates;
    }

    // probably will not be needed since X509 can load bas64 encoded certificate
    // public static function decodeCertificateFromBase64(string $certificateInBase64): X509
    // {
    //     // Objects.requireNonNull(certificateInBase64, "certificateInBase64");

    //     try {
    //         return new X509(Base64Util::decodeBase64($certificateInBase64));
    //     } catch (Throwable $e) {
    //         throw new CertificateDecodingException($e);
    //     }
    // }
}
