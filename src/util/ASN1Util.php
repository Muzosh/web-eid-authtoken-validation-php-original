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

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\SubjectPublicKeyInfo;
use RangeException;
use TypeError;
use UnexpectedValueException;

/**
 * Utility class for handling ASN1 related operations.
 */
final class ASN1Util
{
    public const ID_PKIX_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';

    /**
     * Don't call this, all functions are static.
     *
     * @throws BadFunctionCallException
     *
     * @return never
     */
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * VERY IMPORTANT FUNCTION\
     * During whole validation process, we rely on internal phpseclib3\File\ASN1 list of known OIDs.\
     * If something is not working, there is high probability the OID mapping is missing, so it can be added here.\
     * CALL THIS FUNCTION AT THE START OF VALIDATION PROCESS.
     */
    public static function loadOIDs(): void
    {
        // these were discovered during testing as missing
        ASN1::loadOIDs(array(
            'id-pkix-ocsp-nonce' => self::ID_PKIX_OCSP_NONCE,
            'id-sha1' => '1.3.14.3.2.26',
            'qcStatements(3)' => '1.3.6.1.5.5.7.1.3',
            'street' => '2.5.4.9',
            'id-pkix-ocsp-basic' => '1.3.6.1.5.5.7.48.1.1',
            'id-pkix-ocsp' => '1.3.6.1.5.5.7.48.1',
            'secp384r1' => '1.3.132.0.34',
            'id-pkix-ocsp-archive-cutoff' => '1.3.6.1.5.5.7.48.1.6',
            'id-pkix-ocsp-nocheck' => '1.3.6.1.5.5.7.48.1.5',
        ));
    }

    /**
     * SubjectPublicKeyInfo BER contains ASN1 'algorithm' and 'subjectPublicKey'.
     * We only need the second part.
     *
     * @throws RangeException
     * @throws TypeError
     */
    public static function extractKeyData(string $publicKey): string
    {
        $extractedBER = ASN1::extractBER($publicKey);
        $decodedBER = ASN1::decodeBER($extractedBER);

        $onlySubjectPublicKey = ASN1::asn1map($decodedBER[0], SubjectPublicKeyInfo::MAP)['subjectPublicKey'];

        // Integers in ASN1 lead with 0 byte indicating the integer is positive
        // We need to remove this byte so it can be parsed correctly
        return self::removeFirstByte($onlySubjectPublicKey);
    }

    /**
     * Converts bytestring into array of integers, removes first value from list
     * and returns this list converted back to bytestring.
     *
     * @param string $encoded
     *
     * @return string returns $encoded value without the first byte
     */
    public static function removeFirstByte($encoded): string
    {
        return pack('c*', ...array_slice(unpack('c*', $encoded), 1));
    }

    /** In case of ECDSA, the eID card outputs raw R||S, so we need to trascode it to DER.
     * CURRENTLY NOT USED - might be used in src/validator/AuthTokenSignatureValidator.php:validate().\
     * \
     * This function is translated from Java io.jsonwebtoken.impl.crypto.EllipticCurveProvider:\
     * Copyright (C) 2015 jsonwebtoken.io.
     *
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     *
     * @throws UnexpectedValueException
     */
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
