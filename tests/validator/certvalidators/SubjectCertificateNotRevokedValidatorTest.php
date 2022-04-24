<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\certValidators;

use GuzzleHttp\Psr7\Response;
use muzosh\web_eid_authtoken_validation_php\ocsp\maps\OcspOCSPResponseStatus;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspResponseObject;
use muzosh\web_eid_authtoken_validation_php\testutil\Certificates;
use muzosh\web_eid_authtoken_validation_php\testutil\OcspServiceMaker;
use muzosh\web_eid_authtoken_validation_php\util\TrustedAnchors;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateTrustedValidator;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use muzosh\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;
use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

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
        $this->trustedValidator = new SubjectCertificateTrustedValidator(new TrustedAnchors(array()));
        self::setSubjectCertificateIssuerCertificate($this->trustedValidator);
        $this->estEid2018Cert = Certificates::getJaakKristjanEsteid2018Cert();
    }

    public function testWhenValidAiaOcspResponderConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient($this->ocspClient);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidDesignatedOcspResponderConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider();
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $this->ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidOcspNonceDisabledConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(false);
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $this->ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspUrlIsInvalidThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'http://invalid.invalid');
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $this->ocspClient, $ocspServiceProvider);

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX")
        $result = $validator->validate($this->estEid2018Cert);

        // assertThatCode(() ->
        //     )
        //     .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
        //     .getCause()
        //     .isInstanceOf(IOException.class)
        //     .hasMessageMatching("invalid.invalid: (Name or service not known|"
        //         + "Temporary failure in name resolution)");
    }

    public function testWhenOcspRequestFailsThenThrows(): void
    {
        $this->expectNotToPerformAssertions();
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage('OCSP request was not successful, response: http/');

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'https://web-eid-test.free.beeceptor.com');
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $this->ocspClient, $ocspServiceProvider);

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX")
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspRequestHasInvalidBodyThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse('invalid')
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseIsNotSuccessfulThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::buildOcspResponseBodyWithInternalErrorStatus()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidCertificateIdThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::buildOcspResponseBodyWithInvalidCertificateId()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidSignatureThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::buildOcspResponseBodyWithInvalidSignature()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidResponderCertThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::buildOcspResponseBodyWithInvalidResponderCert()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidTagThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::buildOcspResponseBodyWithInvalidTag()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHas2CertResponsesThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_with_2_responses.der')
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHas2ResponderCertsThenThrows(): void
    {
        $this->expectNotToPerformAssertions();
        // $this->markTestSkipped('It is difficult to make Python and Java CertId equal, needs more work');

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_with_2_responder_certs.der')
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseRevokedThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_revoked.der')
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateRevokedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseUnknownThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, 'https://web-eid-test.free.beeceptor.com');
        $response = self::getResponse(
            pack(
                'c+',
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

        // TODO: try to read the message here
        // $this->expectException(UserCertificateRevokedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseCANotTrustedThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::getOcspResponseBytesFromResources('ocsp_response_unknown.der')
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(CertificateNotTrustedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    public function testWhenNonceDiffersThenThrows(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            self::getResponse(
                pack(
                    'c+',
                    ...self::getOcspResponseBytesFromResources()
                )
            )
        );

        // TODO: try to read the message here
        // $this->expectException(UserCertificateOCSPCheckFailedException::class);
        // $this->expectExceptionMessage("XXX");
        $result = $validator->validate($this->estEid2018Cert);
    }

    private static function buildOcspResponseBodyWithInternalErrorStatus(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $status_offset = 6;
        $ocspResponseBytes[$status_offset] = OcspOCSPResponseStatus::MAP['internalError'];

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
        $ocspResponseBytes[$signature_offset + 5] = 0x01;

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
        return unpack('c*', file_get_contents('../../_resources/'.$resource));
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
        $reflector = new ReflectionProperty('SubjectCertificateTrustedValidator', 'subjectCertificateIssuerCertificate');
        $reflector->setAccessible(true);
        $reflector->setValue($trustedValidator, Certificates::getTestEsteid2018CA());
    }

    private static function getResponse(string $body): Response
    {
        return new Response(200, array('Content-Type' => self::OCSP_RESPONSE), $body, '1.1');
    }
}
