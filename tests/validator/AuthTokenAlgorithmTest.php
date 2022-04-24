<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator;

use muzosh\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use muzosh\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;

/**
 * @internal
 * @coversNothing
 */
class AuthTokenAlgorithmTest extends AbstractTestWithValidator
{
    public function testWhenAlgorithmNoneThenValidationFails(): void
    {
        $this->expectNotToPerformAssertions();
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'ES384', 'NONE');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage('Unsupported signature algorithm');
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }

    public function testWhenAlgorithmEmptyThenParsingFails(): void
    {
        $this->expectNotToPerformAssertions();
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'ES384', '');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'algorithm' is null or empty");
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }

    public function testWhenAlgorithmInvalidThenParsingFails(): void
    {
        $this->expectNotToPerformAssertions();
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'ES384', '\\u0000\\t\\ninvalid');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage('Unsupported signature algorithm');
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }
}
