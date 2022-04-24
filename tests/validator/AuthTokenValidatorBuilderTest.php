<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
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
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Origin URI must not be null');
        self::$builder->build();
    }

    public function testRootCertificateAuthorityMissing(): void
    {
        $builderWithMissingRootCa = (self::$builder)->withSiteOrigin(new Uri('https://ria.ee'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one trusted certificate authority must be provided');
        $builderWithMissingRootCa->build();
    }

    public function testValidatorOriginNotUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Provided URI is not a valid URL');
        AuthTokenValidators::getAuthTokenValidator('not-url');
    }

    public function testValidatorOriginExcessiveElements(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('https://ria.ee/excessive-element');
    }

    public function testValidatorOriginNotHttps(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('http://ria.ee');
    }

    public function testValidatorOriginNotValidUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Origin URI must only contain the HTTPS scheme, host and optional port component');
        AuthTokenValidators::getAuthTokenValidator('ria://ria.ee');
    }

    public function testValidatorOriginNotValidSyntax(): void
    {
        $this->expectException(MalformedUriException::class);
        $this->expectExceptionMessage('Unable to parse URI: https:///ria.ee');
        AuthTokenValidators::getAuthTokenValidator('https:///ria.ee');
    }
}
