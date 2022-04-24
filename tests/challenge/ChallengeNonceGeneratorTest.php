<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class ChallengeNonceGeneratorTest extends TestCase
{
    private ChallengeNonceStore $challengeNonceStore;

    protected function setUp(): void
    {
        $this->challengeNonceStore = new InMemoryChallengeNonceStore();
    }

    public function testValidateNonceGeneration(): void
    {
        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(1)->build();

        $nonce1 = $challengeNonceGenerator->generateAndStoreNonce();
        $nonce2 = $challengeNonceGenerator->generateAndStoreNonce();

        // Base64-encoded 32 bytes = 44 strlen
        $this->assertTrue(44 == strlen($nonce1->getBase64EncodedNonce()));
        $this->assertNotEquals($nonce1->getBase64EncodedNonce(), $nonce2->getBase64EncodedNonce());

        // It might be possible to add an entropy test by compressing the nonce bytes
        // and verifying that the result is longer than for non-random strings.
    }

    public function testValidateUnexpiredNonce()
    {
        $this->expectNotToPerformAssertions();

        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(2)->build();

        $challengeNonceGenerator->generateAndStoreNonce();

        sleep(1);

        $this->challengeNonceStore->getAndRemove();
    }

    public function testValidateNonceExpiration()
    {
        $this->expectException(ChallengeNonceExpiredException::class);
        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(1)->build();

        $challengeNonceGenerator->generateAndStoreNonce();

        sleep(2);

        $this->challengeNonceStore->getAndRemove();
    }

    public function testValidateNonceNotFound()
    {
        $this->expectException(ChallengeNonceNotFoundException::class);
        $this->challengeNonceStore->getAndRemove();
    }
}
