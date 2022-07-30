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

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use BadFunctionCallException;
/**
 * Utility class for specifying subject certificate policy ID constants
 */
final class SubjectCertificatePolicyIds
{
    private const ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX = '1.3.6.1.4.1.10015.1.3';

    public static $ESTEID_SK_2015_MOBILE_ID_POLICY = self::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX;
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V1 = self::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.1';
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V2 = self::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.2';
    public static $ESTEID_SK_2015_MOBILE_ID_POLICY_V3 = self::ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX.'.3';

	/**
     * Don't call this, all functions are static.
     *
     * @throws BadFunctionCallException
     *
     * @return never
     */
    public function __construct()
    {
        throw new BadFunctionCallException('Constants class');
    }
}
