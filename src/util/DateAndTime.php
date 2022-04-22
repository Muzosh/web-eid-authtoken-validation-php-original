<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;
use DateTime;
use DateTimeZone;
use InvalidArgumentException;

final class DateAndTime
{
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function utcNow(): DateTime
    {
        return new DateTime('now', new DateTimeZone('UTC'));
    }

    public static function requirePositiveDuration(int $seconds, string $fieldName): void
    {
        if ($seconds <= 0) {
            throw new InvalidArgumentException($fieldName.' must be greater than zero');
        }
    }

    public static function toUtcString(DateTime $date): string
    {
        return ((clone $date)->setTimezone(new DateTimeZone('UTC')))->format('Y-m-d H:i:s e');
    }
}

final class DefaultClock
{
    private static $instance;

    public static function getInstance()
    {
        if (!isset(self::$instance)) {
            self::$instance = new DefaultClock();
        }

        return self::$instance;
    }

    public function now(): DateTime
    {
        // Specify date.timezone value in php.ini for correct timezone
        return new DateTime();
    }
}
