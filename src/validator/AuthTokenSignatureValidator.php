<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNullOrEmptyException;
use muzosh\web_eid_authtoken_validation_php\util\ASN1Util;
use muzosh\web_eid_authtoken_validation_php\util\Base64Util;
use phpseclib3\Crypt\Common\PublicKey;

class AuthTokenSignatureValidator
{
    // Supported subset of JSON Web Signature algorithms as defined in RFC 7518, sections 3.3, 3.4, 3.5.
    // See https://github.com/web-eid/libelectronic-id/blob/main/include/electronic-id/enums.hpp#L176.
    private const ALLOWED_SIGNATURE_ALGORITHMS = array(
        'ES256', 'ES384', 'ES512', // ECDSA
        'PS256', 'PS384', 'PS512', // RSASSA-PSS
        'RS256', 'RS384', 'RS512', // RSASSA-PKCS1-v1_5
    );

    private string $siteOrigin;

    public function __construct(Uri $siteOrigin)
    {
        $this->siteOrigin = $siteOrigin;
    }

    public function validate(string $algorithm, string $signature, PublicKey $publicKey, string $currentChallengeNonce): void
    {
        $this->requireNotEmpty($algorithm, 'algorithm');
        $this->requireNotEmpty($signature, 'signature');
        if (empty($currentChallengeNonce)) {
            throw new ChallengeNullOrEmptyException();
        }

        if (!in_array($algorithm, AuthTokenSignatureValidator::ALLOWED_SIGNATURE_ALGORITHMS)) {
            throw new AuthTokenParseException('Unsupported signature algorithm');
        }

        $decodedSignature = Base64Util::decodeBase64($signature);
        // Note that in case of ECDSA, the eID card outputs raw R||S, so we need to trascode it to DER.
        if ('ES' == substr($algorithm, 0, 2)) {
            $transcodedBytes = ASN1Util::transcodeSignatureToDER($decodedSignature);

            $decodedSignature = pack('c*', ...$transcodedBytes);
        }

        $hashAlg = $this->hashAlgorithmForName($algorithm);

        $originHash = hash($hashAlg, strval($this->siteOrigin), true);
        $nonceHash = hash($hashAlg, $currentChallengeNonce, true);
        $concatSignedFields = $originHash.$nonceHash;

        $publicKey->withHash($hashAlg)->verify($concatSignedFields, $decodedSignature);
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
