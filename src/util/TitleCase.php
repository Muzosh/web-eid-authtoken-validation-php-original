<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;

// THIS CLASS MIGHT NOT BE USED AT ALL
// TODO: ask an author about this?
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
