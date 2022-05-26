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
