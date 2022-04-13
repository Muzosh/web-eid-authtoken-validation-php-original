<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use DateInterval;
use muzosh\web_eid_authtoken_validation_php\util\Base64Util;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

final class ChallengeNonceGeneratorImpl implements ChallengeNonceGenerator
{
    private $challengeNonceStore;
    private $secureRandom;
    private $ttl;

    public function __construct(ChallengeNonceStore $challengeNonceStore, callable $secureRandom, DateInterval $ttl)
    {
        $this->{$challengeNonceStore} = $challengeNonceStore;
        $this->{$secureRandom} = $secureRandom;
        $this->{$ttl} = $ttl;
    }

    public function generateAndStoreNonce(): ChallengeNonce
    {
        $nonceBytes = call_user_func($this->secureRandom, $this::NONCE_LENGTH);
        $expirationTime = DateAndTime::utcNow()->add($this->ttl);
        $base64Nonce = Base64Util::encodeBase64($nonceBytes);
        $challengeNonce = new ChallengeNonce($base64Nonce, $expirationTime);
        $this->challengeNonceStore->put($this->challengeNonce);

        return $challengeNonce;
    }
}
