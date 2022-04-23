<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use DateInterval;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

final class ChallengeNonceGeneratorImpl implements ChallengeNonceGenerator
{
    private ChallengeNonceStore $challengeNonceStore;
    private $secureRandom;
    private int $ttlSeconds;

    public function __construct(ChallengeNonceStore $challengeNonceStore, callable $secureRandom, int $ttlSeconds)
    {
        $this->challengeNonceStore = $challengeNonceStore;
        $this->secureRandom = $secureRandom;
        $this->ttlSeconds = $ttlSeconds;
    }

    public function generateAndStoreNonce(): ChallengeNonce
    {
        $nonceString = call_user_func($this->secureRandom, $this::NONCE_LENGTH);
        $expirationTime = DateAndTime::utcNow()->add(new DateInterval('PT'.$this->ttlSeconds.'S'));
        $base64Nonce = base64_encode($nonceString);
        $challengeNonce = new ChallengeNonce($base64Nonce, $expirationTime);
        $this->challengeNonceStore->put($challengeNonce);

        return $challengeNonce;
    }
}
