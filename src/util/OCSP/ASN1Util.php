<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp;

use BadFunctionCallException;
use phpseclib3\File\ASN1;
use UnexpectedValueException;

final class ASN1Util
{
    public const ID_PKIX_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
    public const ID_SHA1 = '1.3.14.3.2.26';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function loadOIDs(): void
    {
        // these were discovered during testing as missing
        ASN1::loadOIDs(array(
            'id-pkix-ocsp-nonce' => ASN1Util::ID_PKIX_OCSP_NONCE,
            'id-sha1' => ASN1Util::ID_SHA1,
            'qcStatements(3)' => '1.3.6.1.5.5.7.1.3',
            'street' => '2.5.4.9',
            'id-pkix-ocsp-basic' => '1.3.6.1.5.5.7.48.1.1',
            'id-pkix-ocsp' => '1.3.6.1.5.5.7.48.1',
            'secp384r1' => '1.3.132.0.34',
            'id-pkix-ocsp-archive-cutoff' => '1.3.6.1.5.5.7.48.1.6',
        ));
    }

    public static function extractKeyData(string $publicKey): string
    {
        $extractedBER = ASN1::extractBER($publicKey);
        $decodedBER = ASN1::decodeBER($extractedBER);

        $onlyKeyData = $decodedBER[0]['content'][1]['content'];

        return ASN1Util::removeZeroPaddingFromFirstByte($onlyKeyData);
    }

    public static function removeZeroPaddingFromFirstByte($encoded): string
    {
        return pack('c*', ...array_slice(unpack('c*', $encoded), 1));
    }

    // this function is translated from Java io.jsonwebtoken.impl.crypto.EllipticCurveProvider
    // TODO: is this ok to translate? isnt it some kind of breach of licence?
    /*
    * Copyright (C) 2015 jsonwebtoken.io
    *
    * Licensed under the Apache License, Version 2.0 (the "License");
    * you may not use this file except in compliance with the License.
    * You may obtain a copy of the License at
    *
    *     http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing, software
    * distributed under the License is distributed on an "AS IS" BASIS,
    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    * See the License for the specific language governing permissions and
    * limitations under the License.
    */
    // In case of ECDSA, the eID card outputs raw R||S, so we need to trascode it to DER.
    public static function transcodeSignatureToDER(array $signature): array
    {
        $rawLen = count($signature) / 2;

        $i = $rawLen;

        while (($i > 0) && (0 == $signature[$rawLen - $i])) {
            --$i;
        }

        $j = $i;

        if ($signature[$rawLen - $i] < 0) {
            ++$j;
        }

        $k = $rawLen;

        while (($k > 0) && (0 == $signature[2 * $rawLen - $k])) {
            --$k;
        }

        $l = $k;

        if ($signature[2 * $rawLen - $k] < 0) {
            ++$l;
        }

        $len = 2 + $j + 2 + $l;

        if ($len > 255) {
            throw new UnexpectedValueException('Invalid ECDSA signature format');
        }

        $offset = 0;

        $derSignature = array();

        if ($len < 128) {
            $derSignature = array_fill(0, 2 + 2 + $j + 2 + $l, 0);
            $offset = 1;
        } else {
            $derSignature = array_fill(0, 3 + 2 + $j + 2 + $l, 0);
            $derSignature[1] = 0x81;
            $offset = 2;
        }

        $derSignature[0] = 48;
        $derSignature[$offset++] = $len;
        $derSignature[$offset++] = 2;
        $derSignature[$offset++] = $j;

        $slice = array_slice($signature, $rawLen - $i, $i);
        $destPos = ($offset + $j) - $i;
        foreach ($slice as $key => $value) {
            $derSignature[$destPos + $key] = $value;
        }

        $offset += $j;

        $derSignature[$offset++] = 2;
        $derSignature[$offset++] = $l;

        $slice = array_slice($signature, 2 * $rawLen - $k, $k);
        $destPos = ($offset + $l) - $k;
        foreach ($slice as $key => $value) {
            $derSignature[$destPos + $key] = $value;
        }

        return $derSignature;
    }
}
