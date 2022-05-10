<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use muzosh\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use muzosh\web_eid_authtoken_validation_php\testutil\Certificates;
use muzosh\web_eid_authtoken_validation_php\testutil\OcspServiceMaker;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class OcspServiceProviderTest extends TestCase
{
    public function testWhenDesignatedOcspServiceConfigurationProvidedThenCreatesDesignatedOcspService(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider();
        $service = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());

        $this->assertEquals($service->getAccessLocation(), new Uri('http://demo.sk.ee/ocsp'));
        $this->assertTrue($service->doesSupportNonce());

        $service->validateResponderCertificate(Certificates::getTestSkOcspResponder2020(), new DateTime('Thursday, August 26, 2021 5:46:40 PM'));

        $this->expectException(OCSPCertificateException::class);
        $this->expectExceptionMessage('Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate');
        $service->validateResponderCertificate(Certificates::getTestEsteid2018CA(), new DateTime('Thursday, August 26, 2021 5:46:40 PM'));
    }

    public function testWhenAiaOcspServiceConfigurationProvidedThenCreatesAiaOcspService(): void
    {
		// Had to add TEST_of_EE-GovCA2018.pem.crt
		// to trusted certificates in order to validate responder certificate.
		// TODO: find out why Java test counterpart is OK without them

		// responder certificate issuer is in trusted certificates:
        $ocspServiceProvider = OcspServiceMaker::getAiaOcspServiceProvider();
        $service2018 = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());

        $this->assertEquals($service2018->getAccessLocation(), new Uri('http://aia.demo.sk.ee/esteid2018'));
        $this->assertTrue($service2018->doesSupportNonce());

        $service2018->validateResponderCertificate(Certificates::getTestEsteid2018CA(), new DateTime('Thursday, August 26, 2021 5:46:40 PM'));

		// responder certificate issuer is NOT in trusted certificates:
        $service2015 = $ocspServiceProvider->getService(Certificates::getMariliisEsteid2015Cert());
        $this->assertEquals($service2015->getAccessLocation(), new Uri('http://aia.demo.sk.ee/esteid2015'));
        $this->assertFalse($service2015->doesSupportNonce());

		$this->expectException(CertificateNotTrustedException::class);
		$this->expectExceptionMessage("Certificate C=EE, O=AS Sertifitseerimiskeskus/2.5.4.97=NTREE-10747013, CN=TEST of ESTEID-SK 2015 is not trusted");
        $service2015->validateResponderCertificate(Certificates::getTestEsteid2015CA(), new DateTime('Thursday, August 26, 2021 5:46:40 PM'));
    }

    public function testWhenAiaOcspServiceConfigurationDoesNotHaveResponderCertTrustedCAThenThrows(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getAiaOcspServiceProvider();
        $service2018 = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());
        $wrongResponderCert = Certificates::getMariliisEsteid2015Cert();

        $this->expectException(OCSPCertificateException::class);
        $service2018->validateResponderCertificate($wrongResponderCert, new DateTime('Thursday, August 26, 2021 5:46:40 PM'));
    }
}
