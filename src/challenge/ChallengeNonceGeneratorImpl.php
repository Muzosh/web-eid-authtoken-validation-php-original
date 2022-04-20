<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use DateInterval;
use muzosh\web_eid_authtoken_validation_php\util\Base64Util;
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
        $nonceBytes = call_user_func($this->secureRandom, $this::NONCE_LENGTH);
        $expirationTime = DateAndTime::utcNow()->add(new DateInterval('PT'.$this->ttlSeconds.'S'));
        $base64Nonce = Base64Util::encodeBase64($nonceBytes);
        $challengeNonce = new ChallengeNonce($base64Nonce, $expirationTime);
        $this->challengeNonceStore->put($this->challengeNonce);

        return $challengeNonce;
    }
}
