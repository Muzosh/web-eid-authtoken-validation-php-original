<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\testutil;

use DateTime;
use muzosh\web_eid_authtoken_validation_php\util\DefaultClock;

final class Dates
{
    public static function create(string $iso8601Date): DateTime
    {
        return new DateTime($iso8601Date);
    }

    public static function setMockedCertificateValidatorDate(DateTime $mockedDate): void
    {
        DefaultClock::getInstance()->setMockedClock($mockedDate);
    }

    public static function resetMockedCertificateValidatorDate(): void
    {
        DefaultClock::getInstance()->resetMockedClock();
    }
}
