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
    private static DefaultClock $instance;

    private DateTime $mockedClock;

    public static function getInstance()
    {
        if (!isset(self::$instance)) {
            self::$instance = new DefaultClock();
        }

        return self::$instance;
    }

    public function now(): DateTime
    {
        if (isset($this->mockedClock)) {
            return $this->mockedClock;
        }

        return new DateTime();
    }

    // used for unit testing
    public function setMockedClock(DateTime $mockedClock): void
    {
        $this->mockedClock = $mockedClock;
    }

    // used for unit testing
    public function resetMockedClock(): void
    {
        unset($this->mockedClock);
    }
}
