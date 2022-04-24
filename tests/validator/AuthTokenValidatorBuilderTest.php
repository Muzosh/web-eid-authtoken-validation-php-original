<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\testutil\AuthTokenValidators;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class AuthTokenValidatorBuilderTest extends TestCase
{
    private static AuthTokenValidatorBuilder $builder;

    public static function setUpBeforeClass(): void
    {
        self::$builder = new AuthTokenValidatorBuilder();
    }

    public function testOriginMissing(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Origin URI must not be null');
        self::$builder->build();
    }

    public function testRootCertificateAuthorityMissing(): void
    {
        $this->expectNotToPerformAssertions();

        $builderWithMissingRootCa = (self::$builder)->withSiteOrigin(new Uri('https://ria.ee'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one trusted certificate authority must be provided');
        $builderWithMissingRootCa->build();
    }

    public function testValidatorOriginNotUrl(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(IllegalArgumentException::class);
        $this->expectExceptionMessage('Provided URI is not a valid URL');
        AuthTokenValidators::getAuthTokenValidator('not-url');
    }

    public function testValidatorOriginExcessiveElements(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(IllegalArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('https://ria.ee/excessive-element');
    }

    public function testValidatorOriginNotHttps(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(IllegalArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('http://ria.ee');
    }

    public function testValidatorOriginNotValidUrl(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(IllegalArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('ria://ria.ee');
    }

    public function testValidatorOriginNotValidSyntax(): void
    {
        $this->expectNotToPerformAssertions();

        $this->expectException(MalformedUriException::class);
        $this->expectExceptionMessage('Unable to parse URI: https:///ria.ee');
        AuthTokenValidators::getAuthTokenValidator('https:///ria.ee');
    }
}
