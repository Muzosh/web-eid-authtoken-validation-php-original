<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class OcspResponseValidatorTest extends TestCase
{
    public function testWhenThisUpdateDayBeforeProducedAtThenThrows(): void
    {
        // yyyy-MM-dd'T'HH:mm:ss.SSSZ
        $mockResponse = array(
            'thisUpdate' => '2021-09-01T00:00:00.000Z',
        );
        $producedAt = new DateTime('2021-09-02T00:00:00.000Z');

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage('User certificate revocation check has failed: '
        .'Certificate status update time check failed: '
        .'notAllowedBefore: 2021-09-01 23:45:00 UTC, '
        .'notAllowedAfter: 2021-09-02 00:15:00 UTC, '
        .'thisUpdate: 2021-09-01 00:00:00 UTC, '
        .'nextUpdate: null');
        OcspResponseValidator::validateCertificateStatusUpdateTime($mockResponse, $producedAt);
    }

    public function testWhenThisUpdateDayAfterProducedAtThenThrows(): void
    {
        // yyyy-MM-dd'T'HH:mm:ss.SSSZ
        $mockResponse = array(
            'thisUpdate' => '2021-09-02T00:00:00.000Z',
        );
        $producedAt = new DateTime('2021-09-01T00:00:00.000Z');

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage('User certificate revocation check has failed: '
        .'Certificate status update time check failed: '
        .'notAllowedBefore: 2021-08-31 23:45:00 UTC, '
        .'notAllowedAfter: 2021-09-01 00:15:00 UTC, '
        .'thisUpdate: 2021-09-02 00:00:00 UTC, '
        .'nextUpdate: null');

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockResponse, $producedAt);
    }

    public function testWhenNextUpdateDayBeforeProducedAtThenThrows(): void
    {
        // yyyy-MM-dd'T'HH:mm:ss.SSSZ
        $mockResponse = array(
            'thisUpdate' => '2021-09-02T00:00:00.000Z',
            'nextUpdate' => '2021-09-01T00:00:00.000Z',
        );
        $producedAt = new DateTime('2021-09-02T00:00:00.000Z');

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage('User certificate revocation check has failed: '
        .'Certificate status update time check failed: '
        .'notAllowedBefore: 2021-09-01 23:45:00 UTC, '
        .'notAllowedAfter: 2021-09-02 00:15:00 UTC, '
        .'thisUpdate: 2021-09-02 00:00:00 UTC, '
        .'nextUpdate: 2021-09-01 00:00:00 UTC');
        OcspResponseValidator::validateCertificateStatusUpdateTime($mockResponse, $producedAt);
    }
}
