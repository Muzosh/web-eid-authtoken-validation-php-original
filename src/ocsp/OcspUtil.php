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
