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
    public const CERTPATH = __DIR__.'/../../certs';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function loadCertificatesFromPath(string $certPath, string ...$certificateNames): array
    {
        $caCertificates = array();
        foreach ($certificateNames as $certificateName) {
            $x509 = new X509();
            $test = array(
                __DIR__,
                __FILE__,
            );
            $result = $x509->loadX509(file_get_contents($certPath.'/'.$certificateName));
            if ($result) {
                array_push($caCertificates, $x509);
            } else {
                throw new CertificateDecodingException($certificateName);
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
