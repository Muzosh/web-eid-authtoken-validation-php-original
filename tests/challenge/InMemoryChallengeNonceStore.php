<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

class InMemoryChallengeNonceStore extends ChallengeNonceStore
{
    private ?ChallengeNonce $challengeNonce = null;

    public function put(ChallengeNonce $challengeNonce): void
    {
        $this->challengeNonce = $challengeNonce;
    }

    public function getAndRemoveImpl(): ?ChallengeNonce
    {
        $result = $this->challengeNonce;
        $this->challengeNonce = null;

        return $result;
    }
}
