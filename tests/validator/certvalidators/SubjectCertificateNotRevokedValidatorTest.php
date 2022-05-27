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

namespace muzosh\web_eid_authtoken_validation_php\validator\certvalidators;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Response;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateRevokedException;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspResponseObject;
use muzosh\web_eid_authtoken_validation_php\testutil\Certificates;
use muzosh\web_eid_authtoken_validation_php\testutil\OcspServiceMaker;
use muzosh\web_eid_authtoken_validation_php\util\ASN1Util;
use muzosh\web_eid_authtoken_validation_php\util\TrustedCertificates;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;
use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use UnexpectedValueException;

/**
 * @internal
 * @coversNothing
 */
class SubjectCertificateNotRevokedValidatorTest extends TestCase
{
    private const OCSP_RESPONSE = 'application/ocsp-response';

    private static OcspClient $ocspClient;
    private SubjectCertificateTrustedValidator $trustedValidator;
    private X509 $estEid2018Cert;

    public static function setUpBeforeClass(): void
    {
        self::$ocspClient = OcspClientImpl::build(5);
    }

    protected function setUp(): void
    {
        ASN1Util::loadOIDs();
        $this->trustedValidator = new SubjectCertificateTrustedValidator(new TrustedCertificates(array()));
        self::setSubjectCertificateIssuerCertificate($this->trustedValidator);
        $this->estEid2018Cert = Certificates::getJaakKristjanEsteid2018Cert();
    }

    public function testWhenValidAiaOcspResponderConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient(self::$ocspClient);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidDesignatedOcspResponderConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider();
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidOcspNonceDisabledConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(false);
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspUrlIsInvalidThenThrows(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'http://invalid.invalid');
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(ConnectException::class);
            $this->expectExceptionMessage('Could not resolve host: invalid.invalid');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspRequestFailsThenThrows(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'https://web-eid-test.free.beeceptor.com');
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(ClientException::class);
            $this->expectExceptionMessage('Client error: `POST https://web-eid-test.free.beeceptor.com` resulted in a `404 Not Found` response:');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspRequestHasInvalidBodyThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse('invalid')
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UnexpectedValueException::class);
            $this->expectExceptionMessage('Could not decode OCSP response. Base64 encoded response: aW52YWxpZA==');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseIsNotSuccessfulThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::buildOcspResponseBodyWithInternalErrorStatus()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UnexpectedValueException::class);
            $this->expectExceptionMessage('Could not decode OCSP response. Base64 encoded response: MIIGJwoCAKCCBiAwggYcBgkrBgEFBQcwA');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHasInvalidCertificateIdThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::buildOcspResponseBodyWithInvalidCertificateId()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateOCSPCheckFailedException::class);
            $this->expectExceptionMessage('User certificate revocation check has failed: OCSP responded with certificate ID that differs from the requested ID');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHasInvalidSignatureThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::buildOcspResponseBodyWithInvalidSignature()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateOCSPCheckFailedException::class);
            $this->expectExceptionMessage('User certificate revocation check has failed: OCSP response signature is invalid');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHasInvalidResponderCertThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::buildOcspResponseBodyWithInvalidResponderCert()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage('Unable to perform ASN1 mapping');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHasInvalidTagThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::buildOcspResponseBodyWithInvalidTag()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UnexpectedValueException::class);
            $this->expectExceptionMessage('Could not decode OcspResponse->responseBytes->responseType');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHas2CertResponsesThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_with_2_responses.der')
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateOCSPCheckFailedException::class);
            $this->expectExceptionMessage('User certificate revocation check has failed: OCSP response must contain one response, received 2 responses instead');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseHas2ResponderCertsThenThrows(): void
    {
        $this->markTestSkipped('It is difficult to make Python and Java CertId equal, needs more work');

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_with_2_responder_certs.der')
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateOCSPCheckFailedException::class);
            $this->expectExceptionMessage('User certificate revocation check has failed: OCSP response must contain one response, received 2 certificates instead');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseRevokedThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_revoked.der')
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateRevokedException::class);
            $this->expectExceptionMessage('User certificate has been revoked: Revocation reason: unspecified');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseUnknownThenThrows(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'https://web-eid-test.free.beeceptor.com');
        $response = self::getResponse(
            pack(
                'c*',
                ...self::getOcspResponseBytesFromResources('ocsp_response_unknown.der')
            )
        );
        $client = new class($response) implements OcspClient {
            private $response;

            public function __construct($response)
            {
                $this->response = $response;
            }

            public function request($url, $request): OcspResponseObject
            {
                return new OcspResponseObject($this->response->getBody()->getContents());
            }
        };

        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $client, $ocspServiceProvider);

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateRevokedException::class);
            $this->expectExceptionMessage('User certificate has been revoked: Unknown status');

            throw $e->getPrevious();
        }
    }

    public function testWhenOcspResponseCANotTrustedThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_unknown.der')
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(CertificateNotTrustedException::class);
            $this->expectExceptionMessage('Certificate C=EE, O=AS Sertifitseerimiskeskus, OU=OCSP, CN=TEST of SK OCSP RESPONDER 2020/emailAddress=pki@sk.ee is not trusted');

            throw $e->getPrevious();
        }
    }

    public function testWhenNonceDiffersThenThrows(): void
    {
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c*',
                    ...self::getOcspResponseBytesFromResources()
                )
            )
        );

        try {
            $validator->validate($this->estEid2018Cert);
        } catch (UserCertificateOCSPCheckFailedException $e) {
            $this->assertEquals('User certificate revocation check has failed: Check previous exception', $e->getMessage());

            $this->expectException(UserCertificateOCSPCheckFailedException::class);
            $this->expectExceptionMessage('OCSP request and response nonces differ, possible replay attack');

            throw $e->getPrevious();
        }
    }

    private static function buildOcspResponseBodyWithInternalErrorStatus(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $status_offset = 6;
        // 2 = internal error
        $ocspResponseBytes[$status_offset] = 2;

        return $ocspResponseBytes;
    }

    private static function buildOcspResponseBodyWithInvalidCertificateId(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $certificate_id_offset = 234;
        $ocspResponseBytes[$certificate_id_offset + 3] = 0x42;

        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidSignature(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $signature_offset = 349;
        $ocspResponseBytes[$signature_offset + 5 + 1] = 0x01;

        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidResponderCert(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $certificate_offset = 935;
        $ocspResponseBytes[$certificate_offset + 3] = 0x42;

        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidTag(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $tag_offset = 352;
        $ocspResponseBytes[$tag_offset] = 0x42;

        return $ocspResponseBytes;
    }

    // Either write the bytes of a real OCSP response to a file or use Python and asn1crypto.ocsp
    // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py
    // and https://gist.github.com/mrts/bb0dcf93a2b9d2458eab1f9642ee97b2.
    private static function getOcspResponseBytesFromResources(string $resource = 'ocsp_response.der'): array
    {
        return unpack('c*', file_get_contents(__DIR__.'/../../_resources/'.$resource));
    }

    private function getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(Response $response): SubjectCertificateNotRevokedValidator
    {
        $client = new class($response) implements OcspClient {
            private $response;

            public function __construct($response)
            {
                $this->response = $response;
            }

            public function request($url, $request): OcspResponseObject
            {
                return new OcspResponseObject($this->response->getBody()->getContents());
            }
        };

        return self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient($client);
    }

    private function getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient(OcspClient $client): SubjectCertificateNotRevokedValidator
    {
        return new SubjectCertificateNotRevokedValidator($this->trustedValidator, $client, OcspServiceMaker::getAiaOcspServiceProvider());
    }

    private static function setSubjectCertificateIssuerCertificate(SubjectCertificateTrustedValidator $trustedValidator): void
    {
        $reflector = new ReflectionProperty(SubjectCertificateTrustedValidator::class, 'subjectCertificateIssuerCertificate');
        $reflector->setAccessible(true);
        $reflector->setValue($trustedValidator, Certificates::getTestEsteid2018CA());
    }

    private static function getResponse(string $body): Response
    {
        return new Response(200, array('Content-Type' => self::OCSP_RESPONSE), $body, '1.1');
    }
}
