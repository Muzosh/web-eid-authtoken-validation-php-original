<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

# TODO: finish this

import io.jsonwebtoken.Clock;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Objects;

final class DateAndTime {

    public static ZonedDateTime utcNow() {
        return ZonedDateTime.now(ZoneOffset.UTC);
    }

    public static void requirePositiveDuration(Duration duration, String fieldName) {
        Objects.requireNonNull(duration, fieldName + " must not be null");
        if (duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(fieldName + " must be greater than zero");
        }
    }

    public static class DefaultClock implements Clock {

        public static final Clock INSTANCE = new DefaultClock();

        public Date now() {
            return new Date();
        }

    }

	public function __construct()
	{
		throw new IllegalStateException("Utility class");
	}

}
