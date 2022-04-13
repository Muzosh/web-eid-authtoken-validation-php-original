<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use DateInterval;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;
use UnexpectedValueException;

/**
 * Builder for constructing ChallengeNonceGenerator instances.
 */
class ChallengeNonceGeneratorBuilder
{
    private $challengeNonceStore;
    private $ttl;
    private $secureRandom;

    public function __construct()
    {
        $this->ttl = new DateInterval('PT5M');

        $this->secureRandom = function ($nonce_length) {
            return unpack('c*', random_bytes($nonce_length));
        };
    }

    /**
     * Override default nonce time-to-live duration.
     * When the time-to-live passes, the nonce is considered to be expired.
     *
     * @param duration time-to-live duration
     *
     * @return current builder instance
     */
    public function withNonceTtl(DateInterval $duration): ChallengeNonceGeneratorBuilder
    {
        $this->ttl = $duration;

        return $this;
    }

    /**
     * Sets the challenge nonce store where the generated challenge nonces will be stored.
     *
     * @param challengeNonceStore challenge nonce store
     *
     * @return current builder instance
     */
    public function withChallengeNonceStore(ChallengeNonceStore $challengeNonceStore): ChallengeNonceGeneratorBuilder
    {
        $this->challengeNonceStore = $challengeNonceStore;

        return $this;
    }

    /**
     * Sets the source of random bytes for the nonce.
     *
     * @param secureRandom secure random generator
     *
     * @return current builder instance
     */
    public function withSecureRandom(callable $secureRandom): ChallengeNonceGeneratorBuilder
    {
        $this->secureRandom = $secureRandom;

        return $this;
    }

    /**
     * Validates the configuration and builds the ChallengeNonceGenerator instance.
     *
     * @return ChallengeNonceGenerator new challenge nonce generator instance
     */
    public function build(): ChallengeNonceGenerator
    {
        $this->validateParameters();

        return new ChallengeNonceGeneratorImpl($this->challengeNonceStore, $this->secureRandom, $this->ttl);
    }

    private function validateParameters(): void
    {
        if (is_null($this->challengeNonceStore)) {
            throw new UnexpectedValueException('Challenge nonce store must not be null');
        }
        if (is_null($this->secureRandom)) {
            throw new UnexpectedValueException('Secure random generator must not be null');
        }
        DateAndTime::requirePositiveDuration($this->ttl, 'Nonce TTL');
    }
}
