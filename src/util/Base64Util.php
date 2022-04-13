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

    public static function decodeBase64(string $base64Str): array
    {
        return unpack('c*', base64_decode($base64Str));
    }

    public static function encodeBase64(array $bytes): string
    {
        return base64_encode(pack('c*', ...$bytes));
    }
}
