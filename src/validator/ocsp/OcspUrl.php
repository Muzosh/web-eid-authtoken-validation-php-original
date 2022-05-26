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

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;
use Throwable;

final class OcspUrl
{
    public const AIA_ESTEID_2015_URL = 'http://aia.sk.ee/esteid2015';

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * Returns the OCSP responder URI or null if it doesn't have one.
     */
    public static function getOcspUri(X509 $certificate): ?Uri
    {
        $authorityInformationAccess = $certificate->getExtension('id-pe-authorityInfoAccess');

        try {
            if ($authorityInformationAccess) {
                foreach ($authorityInformationAccess as $accessDescription) {
                    if (('id-pkix-ocsp' === $accessDescription['accessMethod'] || 'id-ad-ocsp' === $accessDescription['accessMethod']) && array_key_exists('uniformResourceIdentifier', $accessDescription['accessLocation'])) {
                        $accessLocationUrl = $accessDescription['accessLocation']['uniformResourceIdentifier'];

                        try {
                            return new Uri($accessLocationUrl);
                        } catch (MalformedUriException $e) {
                            throw new MalformedUriException("OCSP Uri from certificate '".$certificate->getSubjectDN(X509::DN_STRING)."' is invalid", -1, $e);
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            return null;
        }

        return null;
    }
}
