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

namespace muzosh\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\GeneralName;

abstract class OcspTbsRequest
{
    public const MAP = array(
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => array(
            'version' => array(
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
                'mapping' => array(0 => 'v1'),
                'default' => 'v1',
                'type' => ASN1::TYPE_INTEGER,
            ),
            'requestList' => OcspRequests::MAP,
            'requestExtensions' => array(
                'constant' => 2,
                'explicit' => true,
                'optional' => true,
            ) + Extensions::MAP,
            // requestorName needs to be last because it throws out annoying undefined index notices - probably some miss step in the phpseclib library
            // ==> checks for CHOICE are done by map before handling the value by decoded type
            // ==> so library thinks it should be CHOICE before actually knowing it - if it is actually CHOICE, good for everyone - if it is not, library wrongfuly assumes that decoded['constant'] exists
            // ==> so PHP throws Undefined index notice, but program moves on - actuall right decoded type will still be handled later
            'requestorName' => array(
                'constant' => 1,
                'optional' => true,
                'explicit' => true,
            ) + GeneralName::MAP,
        ),
    );
}
