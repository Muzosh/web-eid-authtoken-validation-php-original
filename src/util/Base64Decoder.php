<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

# TODO: find alternative to Base64 and IllegalStateException+IllegalArgumentException
import java.util.Base64;

final class Base64Decoder {

	public function __construct()
	{
		throw new IllegalStateException("Utility class");
	}

    public static byte[] decodeBase64(String base64Str) throws IllegalArgumentException {
        return Base64.getDecoder().decode(base64Str);
    }
}
