<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;
use DateInterval;
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

    public static function requirePositiveDuration(DateInterval $duration, string $fieldName): void
    {
        // This check is automatic since PHP 7.1
        // Objects.requireNonNull(duration, fieldName + " must not be null");

        if ($duration->invert || (array) $duration === (array) new DateInterval('P0Y')) {
            throw new InvalidArgumentException($fieldName.' must be greater than zero');
        }
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
