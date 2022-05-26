<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class OcspUrlTest extends TestCase
{
    public function testWhenExtensionValueIsNullThenReturnsNull()
    {
        $stubCertificate = $this->createStub(X509::class);
        $stubCertificate->method('getExtension')->willReturn(null);

        $this->assertNull(OcspUrl::getOcspUri($stubCertificate));
    }

    // Uri in PHP is not as strict as in Java, so Uris with these bytes get created
    // and there is no way of us to invoke error other than check for isAbsolute
    // which is done and handled later in the program
    // public function testWhenExtensionValueIsInvalidThenReturnsNull()
    // {
    //     $stubCertificate = $this->createStub(X509::class);
    //     $stubCertificate->method('getExtension')->willReturn(
    //         array(
    //             array(
    //                 'accessMethod' => 'id-ad-ocsp',
    //                 'accessLocation' => array(
    //                     'uniformResourceIdentifier' => pack('c*', ...array(1, 2, 3)),
    //                 ),
    //             ),
    //         )
    //     );

    //     $this->assertNull(OcspUrl::getOcspUri($stubCertificate));
    // }

    // public function testWhenExtensionValueIsNotAiaThenReturnsNull()
    // {
    //     $stubCertificate = $this->createStub(X509::class);
    //     $stubCertificate->method('getExtension')->willReturn(
    //         array(
    //             array(
    //                 'accessMethod' => 'id-ad-ocsp',
    //                 'accessLocation' => array(
    //                     'uniformResourceIdentifier' => pack('c*', ...array(4, 64, 48, 62, 48, 50, 6, 11, 43, 6, 1, 4, 1, -125, -111, 33, 1, 2, 1, 48,
    //                         35, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 21, 104, 116, 116, 112, 115,
    //                         58, 47, 47, 119, 119, 119, 46, 115, 107, 46, 101, 101, 47, 67, 80, 83, 48,
    //                         8, 6, 6, 4, 0, -113, 122, 1, 2, )),
    //                 ),
    //             ),
    //         )
    //     );

    //     $this->assertNull(OcspUrl::getOcspUri($stubCertificate));
    // }
}
