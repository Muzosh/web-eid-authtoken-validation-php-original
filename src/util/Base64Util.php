<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;

final class Base64Util
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function decodeBase64ToArray(string $base64Str): array
    {
        return array_values(unpack('c*', base64_decode($base64Str)));
    }

    public static function encodeBase64FromArray(array $bytes): string
    {
        return base64_encode(pack('c*', ...$bytes));
    }
}
