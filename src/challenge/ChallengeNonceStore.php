<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

interface ChallengeNonceStoreInterface {

    public function put(ChallengeNonce $challengeNonce) : void;

    public function getAndRemoveImpl(): ChallengeNonce;

	public function getAndRemove() : ChallengeNonce;
}
/**
 * A store for storing generated challenge nonces and accessing their generation time.
 */
abstract class ChallengeNonceStore implements ChallengeNonceStoreInterface {
    public function getAndRemove() : ChallengeNonce{
        $challengeNonce = $this->getAndRemoveImpl();
        if ($challengeNonce == null) {
            throw new ChallengeNonceNotFoundException();
        }
        if (DateAndTime::utcNow() > $challengeNonce->getExpirationTime()) {
            throw new ChallengeNonceExpiredException();
        }
        return $challengeNonce;
    }
}

