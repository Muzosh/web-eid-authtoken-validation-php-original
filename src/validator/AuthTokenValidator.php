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

namespace muzosh\web_eid_authtoken_validation_php\validator;

use muzosh\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use phpseclib3\File\X509;

/**
 * Parses and validates the provided Web eID authentication token.
 */
interface AuthTokenValidator
{
    public const CURRENT_TOKEN_FORMAT_VERSION = 'web-eid:1';

    /**
     * Parses the Web eID authentication token signed by the subject.
     *
     * @param string $authToken the Web eID authentication token string, in Web eID JSON format
     */
    public function parse(string $authToken): WebEidAuthToken;

    /**
     * Validates the Web eID authentication token signed by the subject and returns
     * the subject certificate that can be used for retrieving information about the subject.
     *
     * See CertificateData and TitleCase for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param WebEidAuthToken $authToken             the Web eID authentication token
     * @param string          $currentChallengeNonce the challenge nonce that is associated with the authentication token
     */
    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509;
}
