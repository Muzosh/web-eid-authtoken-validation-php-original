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

namespace muzosh\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenSignatureValidationException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNullOrEmptyException;
use muzosh\web_eid_authtoken_validation_php\util\ASN1Util;
use muzosh\web_eid_authtoken_validation_php\util\Base64Util;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\DssSigValue;
use phpseclib3\Math\BigInteger;

class AuthTokenSignatureValidator
{
    // Supported subset of JSON Web Signature algorithms as defined in RFC 7518, sections 3.3, 3.4, 3.5.
    // See https://github.com/web-eid/libelectronic-id/blob/main/include/electronic-id/enums.hpp#L176.
    private const ALLOWED_SIGNATURE_ALGORITHMS = array(
        'ES256', 'ES384', 'ES512', // ECDSA
        'PS256', 'PS384', 'PS512', // RSASSA-PSS
        'RS256', 'RS384', 'RS512', // RSASSA-PKCS1-v1_5
    );

    private Uri $siteOrigin;

    public function __construct(Uri $siteOrigin)
    {
        $this->siteOrigin = $siteOrigin;
    }

    public function validate(string $algorithm, string $base64Sig, $publicKey, string $currentChallengeNonce): void
    {
        $this->requireNotEmpty($algorithm, 'algorithm');
        $this->requireNotEmpty($base64Sig, 'signature');

        if (is_null($publicKey)) {
            throw new InvalidArgumentException('Public key is null');
        }

        if (empty($currentChallengeNonce)) {
            throw new ChallengeNullOrEmptyException();
        }

        if (!in_array($algorithm, self::ALLOWED_SIGNATURE_ALGORITHMS)) {
            throw new AuthTokenParseException('Unsupported signature algorithm: '.$algorithm);
        }

        $derSig = base64_decode($base64Sig);

        // Note that in case of ECDSA, some eID cards output raw R||S, so we need to trascode it to DER
        // Second condition actually checks, whether it is possible to map DER into DssSigValue (sequence with two integers)
        if ('ES' == substr($algorithm, 0, 2) && !ASN1::asn1map(ASN1::decodeBER($derSig)[0], DssSigValue::MAP)) {
            // Mapping was unsucessfull - there are two ways of transforming R||S into DER encoded ECC key:
            // 1) split DER encoded string in half, create corresponding array and encode it using the same mapping
            $splittedSig = str_split($derSig, intdiv(strlen($derSig), 2));
            $dssSigValue = array(
                'r' => new BigInteger($splittedSig[0], 256),
                's' => new BigInteger($splittedSig[1], 256),
            );
            $derSig = ASN1::encodeDER($dssSigValue, DssSigValue::MAP);

            // 2) use algorithm similar to one which is used in io.jsonwebtoken.impl.crypto.EllipticCurveProvider Java library:
            // $transcodedBytes = ASN1Util::transcodeSignatureToDER(Base64Util::decodeBase64ToArray($base64Sig));
            // $derSig = pack('c*', ...$transcodedBytes);
        }

        $hashAlg = $this->hashAlgorithmForName($algorithm);

        $originHash = hash($hashAlg, strval($this->siteOrigin), true);
        $nonceHash = hash($hashAlg, $currentChallengeNonce, true);
        $concatSignedFields = $originHash.$nonceHash;

        // general interface PublicKey does not have withHash method so with scrict_types it cannot be type hinted
        // its EC and RSA implementations have it, but multiple type hints ECPublicKey|RSAPublicKey are possible from PHP 8.0
        $result = $publicKey->withHash($hashAlg)->verify($concatSignedFields, $derSig);

        if (!$result) {
            throw new AuthTokenSignatureValidationException();
        }
    }

    private function hashAlgorithmForName(string $algorithm): string
    {
        $hashAlg = 'sha'.substr($algorithm, -3);
        if (!in_array($hashAlg, hash_algos())) {
            throw new AuthTokenParseException("Invalid hash algorithm: {$algorithm}");
        }

        return $hashAlg;
    }

    private function requireNotEmpty(string $argument, string $fieldName): void
    {
        if (empty($argument)) {
            throw new AuthTokenParseException("'".$fieldName."' is null or empty");
        }
    }
}
