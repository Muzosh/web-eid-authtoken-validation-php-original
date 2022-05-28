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
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use phpseclib3\File\X509;
use RangeException;
use RuntimeException;
use TypeError;

/**
 * Utility class for loading certificates.
 */
final class CertificateLoader
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
	 * Loads certificate files from given path into array of phpseclib3\File\X509 objects
	 * @param string $certPath directory path where to look for certificates
	 * @param string ...$certificateNames multiple file names of certificates to load
	 * @return array array of phpseclib3\file\X509 objects
	 * @throws RangeException
	 * @throws TypeError
	 * @throws RuntimeException
	 * @throws CertificateDecodingException
	 */
    public static function loadCertificatesFromPath(string $certPath, string ...$certificateNames): array
    {
        $caCertificates = array();
        foreach ($certificateNames as $certificateName) {
            $x509 = new X509();
            $result = $x509->loadX509(file_get_contents($certPath.'/'.$certificateName));
            if ($result) {
                array_push($caCertificates, $x509);
            } else {
                throw new CertificateDecodingException($certificateName);
            }
        }

        return $caCertificates;
    }
}
