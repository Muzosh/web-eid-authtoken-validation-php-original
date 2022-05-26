<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\ocsp;

use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspBasicOcspResponse;
use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspOCSPResponse;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\X509;
use UnexpectedValueException;

class OcspResponseObject
{
    public const ID_PKIX_OCSP_BASIC_STRING = 'id-pkix-ocsp-basic';
    private array $ocspResponse = array();

    public function __construct(string $encodedBER)
    {
        $decodedResponse = ASN1::decodeBER($encodedBER);

        if (!$decodedResponse[0]) {
            throw new UnexpectedValueException('Could not decode OCSP response. Base64 encoded response: '.base64_encode($encodedBER));
        }

        $this->ocspResponse = ASN1::asn1map(
            $decodedResponse[0],
            OcspOCSPResponse::MAP,
            array('response' => function ($encoded) {
                return ASN1::asn1map(ASN1::decodeBER($encoded)[0], OcspBasicOcspResponse::MAP);
            })
        );

        /* // moved to SubjectCertificateNotRevokedValidator
        if (isset($this->ocspResponse['responseBytes']['response']['certs'])) {
            foreach ($this->ocspResponse['responseBytes']['response']['certs'] as &$cert) {
                // We need to re-encode each responder certificate array as there exists some
                // more loading in X509->loadX509 method, which is not executed when loading just basic array.
                // For example without this the publicKey would not be in PEM format
                // and X509->getPublicKey() will throw error.
                $x509 = new X509();
                $cert = $x509->loadX509(ASN1::encodeDER($cert, Certificate::MAP));
                unset($x509);
            }
        } */
    }

    public function getStatus(): string
    {
        return $this->ocspResponse['responseStatus'];
    }

    public function getBasicResponse(): BasicResponseObject
    {
        if (self::ID_PKIX_OCSP_BASIC_STRING != $this->ocspResponse['responseBytes']['responseType']) {
            throw new UnexpectedValueException(
                'OcspResponse->responseBytes->responseType is not "id-pkix-ocsp-basic": '.
                $this->ocspResponse['responseBytes']['responseType']
            );
        }

        if (!$this->ocspResponse['responseBytes']['response']) {
            throw new UnexpectedValueException('Could not decode OcspResponse->responseBytes->responseType');
        }

        return new BasicResponseObject($this->ocspResponse['responseBytes']['response']);
    }
}
