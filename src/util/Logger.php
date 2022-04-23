<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

final class WebEidLogger
{
    public static function getLogger(string $class): Logger
    {
        $logger = new Logger($class);

        // TODO: put file location to config or global constant
        $handler = new StreamHandler('web-eid-authtoken-validation-php.log', Logger::DEBUG, true, null, true);

        // $handler->setFormatter(new LineFormatter(null, null, true, false, true));
        $handler->setFormatter(new JsonFormatter());

        $logger->pushHandler($handler);

        return $logger;
    }
}
