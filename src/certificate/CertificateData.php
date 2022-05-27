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
use BadMethodCallException;
use LengthException;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\File\X509;
use SodiumException;
use TypeError;
use UnexpectedValueException;

/* in java code there is some special x500 formating?
according to the tests there should be backslashes before dashes?
why is it converting to JcaX509CertificateHolder object?
Example value from java formatting (notice the backslashes):
    [C=EE, CN=JÕEORG\,JAAK-KRISTJAN\,38001085718, 2.5.4.4=#0c074ac395454f5247, 2.5.4.42=#0c0d4a41414b2d4b524953544a414e, 2.5.4.5=#1311504e4f45452d3338303031303835373138]
* this probably is not issue in PHP - it might however raise some compatibility issues when using both validation libraries in some workflow
*/

/**
 * Utility class for extracting data from phpseclib3\File\X509 object.
 */
final class CertificateData
{
    /**
     * Don't call this, all functions are static.
     *
     * @throws BadFunctionCallException
     *
     * @return never
     */
    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * Gets id-at-commonName from x509 certificate.
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectCN(X509 $certificate): string
    {
        return self::getSubjectField($certificate, 'id-at-commonName');
    }

    /**
     * Gets id-at-surname from x509 certificate.
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectSurname(X509 $certificate): string
    {
        return self::getSubjectField($certificate, 'id-at-surname');
    }

    /**
     * Gets id-at-surname from x509 certificate.
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectGivenName(X509 $certificate): string
    {
        return self::getSubjectField($certificate, 'id-at-givenName');
    }

    /**
     * Gets id-at-serialNumber from x509 certificate.
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectSerialNumber(X509 $certificate): string
    {
        return self::getSubjectField($certificate, 'id-at-serialNumber');
    }

    /**
     * Gets id-at-countryName from x509 certificate.
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectCountryCode(X509 $certificate): string
    {
        return self::getSubjectField($certificate, 'id-at-countryName');
    }

    /**
     * Gets specified subject field.
     *
     * @throws InsufficientSetupException
     * @throws LengthException
     * @throws BadMethodCallException
     * @throws SodiumException
     * @throws TypeError
     * @throws UnexpectedValueException
     */
    private static function getSubjectField(X509 $certificate, string $fieldIdentifier): string
    {
        $result = $certificate->getSubjectDNProp($fieldIdentifier);

        if ($result) {
            return $result[0];
        }

        throw new UnexpectedValueException('fieldIdentifier '.$fieldIdentifier.' not found in certificate: '.$certificate->getDN(X509::DN_STRING));
    }
}
