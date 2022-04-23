<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;

// TODO: THIS CLASS MIGHT NOT BE USED AT ALL
// in java it is used only in testing
final class TitleCase
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function toTitleCase(string $input): string
    {
        return ucwords($input, " \t\r\n\f\v\\-");
    }
}
