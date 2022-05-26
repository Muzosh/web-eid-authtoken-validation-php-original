<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp;

use BadFunctionCallException;
use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Name;
use phpseclib3\File\X509;

final class OcspUtil
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function getCertificateId(X509 $subjectCert, X509 $issuerCert, string $hashAlg = 'sha1'): array
    {
        $certId = array(
            'hashAlgorithm' => array(),
            'issuerNameHash' => '',
            'issuerKeyHash' => '',
            'serialNumber' => array(),
        );

        // serial number
        if (!isset($subjectCert->getCurrentCert()['tbsCertificate']['serialNumber'])) {
            throw new OCSPCertificateException('Serial number of subject certificate does not exist');
        }
        $certId['serialNumber'] = clone $subjectCert->getCurrentCert()['tbsCertificate']['serialNumber'];

        // issuer name
        if (!isset($issuerCert->getCurrentCert()['tbsCertificate']['subject'])) {
            throw new OCSPCertificateException('Serial number of issuer certificate does not exist');
        }
        $issuer = $issuerCert->getCurrentCert()['tbsCertificate']['subject'];
        $issuerEncoded = ASN1::encodeDER($issuer, Name::MAP);
        $certId['issuerNameHash'] = hash($hashAlg, $issuerEncoded, true);

        // issuer public key
        if (!isset($issuerCert->getCurrentCert()['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'])) {
            throw new OCSPCertificateException('SubjectPublicKey of issuer certificate does not exist');
        }
        $publicKey = $issuerCert->getCurrentCert()['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];

        $pureKeyData = ASN1Util::extractKeyData($publicKey);

        $certId['issuerKeyHash'] = hash($hashAlg, $pureKeyData, true);

        // hashAlgorithm
        // sha1 is hardcoded
        if ('sha1' !== $hashAlg) {
            throw new InvalidArgumentException('Not implemented yet. SHA1 is used as default for speed');
        }
        $certId['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        return $certId;
    }
}
