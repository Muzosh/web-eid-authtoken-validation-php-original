<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

/**
 * A store for storing generated challenge nonces and accessing their generation time.
 */
abstract class ChallengeNonceStore
{
    abstract public function put(ChallengeNonce $challengeNonce): void;

    abstract public function getAndRemoveImpl(): ?ChallengeNonce;

    public function getAndRemove(): ChallengeNonce
    {
        $challengeNonce = $this->getAndRemoveImpl();
        if (null == $challengeNonce) {
            throw new ChallengeNonceNotFoundException();
        }
        if (DateAndTime::utcNow() > $challengeNonce->getExpirationTime()) {
            throw new ChallengeNonceExpiredException();
        }

        return $challengeNonce;
    }
}
