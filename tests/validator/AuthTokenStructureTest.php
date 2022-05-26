<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;

/**
 * @internal
 * @coversNothing
 */
class AuthTokenStructureTest extends AbstractTestWithValidator
{
    /* this cannot happened, PHP does not have nullable string
    public function testWhenNullToken_thenParsingFails():void {
    	$this->expectNotToPerformAssertions();
    	$this->expectException(AuthTokenParseException::class);
    	$this->expectExceptionMessage("Auth token is null or too short");

    	$this->validator->parse(null);
    } */

    public function testWhenNullStrTokenThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage('Auth token is null or too short');
        $this->validator->parse('null');
    }

    public function testWhenTokenTooShortThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage('Auth token is null or too short');
        $this->validator->parse(str_repeat('1', 99));
    }

    public function testWhenTokenTooLongThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage('Auth token is too long');
        $this->validator->parse(str_repeat('1', 10001));
    }

    public function testWhenUnknownTokenVersionThenParsingFails(): void
    {
        $token = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'web-eid:1', 'invalid');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Only token format version 'web-eid:1' is currently supported");

        $this->validator->validate($token, '');
    }
}
