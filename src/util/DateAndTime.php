<?php

/* The MIT License (MIT)
*
* Copyright (c) 2022 Petr Muzikant <pmuzikant@email.cz>
*
* > Permission is hereby granted, free of charge, to any person obtaining a copy
* > of this software and associated documentation files (the "Software"), to deal
* > in the Software without restriction, including without limitation the rights
* > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* > copies of the Software, and to permit persons to whom the Software is
* > furnished to do so, subject to the following conditions:
* >
* > The above copyright notice and this permission notice shall be included in
* > all copies or substantial portions of the Software.
* >
* > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* > THE SOFTWARE.
*/

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

    public static function toUtcString(?DateTime $date): string
    {
        if (is_null($date)) {
            return 'null';
        }

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
