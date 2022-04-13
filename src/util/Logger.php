<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use Monolog\Handler\StreamHandler;
use Monolog\Logger;

final class WebEidLogger
{
    public static function getLogger($class): Logger
    {
		// TODO: put this to config or global constant
        $logger = new Logger($class);
        $logger->pushHandler(new StreamHandler('web-eid-authtoken-validation-php.log', Logger::DEBUG, true, null, true));

        return $logger;
    }
}
