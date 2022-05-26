<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use phpseclib3\File\X509;
use Throwable;

final class CertificateLoader
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function loadCertificatesFromPath(string $certPath, string ...$certificateNames): array
    {
        $caCertificates = array();
        foreach ($certificateNames as $certificateName) {
            $x509 = new X509();
            $result = $x509->loadX509(file_get_contents($certPath.'/'.$certificateName));
            if ($result) {
                array_push($caCertificates, $x509);
            } else {
                throw new CertificateDecodingException($certificateName);
            }
        }

        return $caCertificates;
    }
}
