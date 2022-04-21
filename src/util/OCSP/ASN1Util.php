<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util\ocsp;

use BadFunctionCallException;
use phpseclib3\File\ASN1;
use UnexpectedValueException;

final class ASN1Util
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function loadOIDs(): void
    {
        ASN1::loadOIDs(array(
            'id-pkix-ocsp-nonce' => '1.3.6.1.5.5.7.48.1.2',
            'id-sha1' => '1.3.14.3.2.26',
            'qcStatements(3)' => '1.3.6.1.5.5.7.1.3',
            'street' => '2.5.4.9',
            'id-pkix-ocsp-basic' => '1.3.6.1.5.5.7.48.1.1',
            'id-pkix-ocsp' => '1.3.6.1.5.5.7.48.1',
            'secp384r1' => '1.3.132.0.34',
        ));
    }

    // this function is translated from Java io.jsonwebtoken.impl.crypto
    // TODO: is this ok to translated? isnt it some kind of breach of licence?
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

        // src, srcPos, dest, destPos, len
        // System.arraycopy($signature, 2 * $rawLen - $k, $derSignature, ($offset + $l) - $k, $k);
        $slice = array_slice($signature, 2 * $rawLen - $k, $k);
        $destPos = ($offset + $l) - $k;
        foreach ($slice as $key => $value) {
            $derSignature[$destPos + $key] = $value;
        }

        return $derSignature;
    }
}
