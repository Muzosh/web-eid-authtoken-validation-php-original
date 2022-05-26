<?php

/* The MIT License (MIT)
*
* Copyright (c) 2022 Petr Muzikant <pmuzikant@email.cz>
*
* > Permission is hereby granted, free of charge, to any person obtaining a copy
* > of this software and associated documentation files (the "Software"), to deal
* > in the Software without restriction, including without limitation the rights
* > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* > copies of the Software, and to permit persons to whom the Software is
* > furnished to do so, subject to the following conditions:
* >
* > The above copyright notice and this permission notice shall be included in
* > all copies or substantial portions of the Software.
* >
* > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* > THE SOFTWARE.
*/

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

/**
 * Builder for constructing ChallengeNonceGenerator instances.
 */
class ChallengeNonceGeneratorBuilder
{
    private ChallengeNonceStore $challengeNonceStore;
    private $secureRandom;
    private int $ttlSeconds;

    public function __construct()
    {
        $this->ttlSeconds = 300; // 5 minutes

        $this->secureRandom = function ($nonce_length) {
            return random_bytes($nonce_length);
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
    public function withNonceTtl(int $seconds): ChallengeNonceGeneratorBuilder
    {
        $this->ttlSeconds = $seconds;

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

        return new ChallengeNonceGeneratorImpl($this->challengeNonceStore, $this->secureRandom, $this->ttlSeconds);
    }

    private function validateParameters(): void
    {
        if (is_null($this->challengeNonceStore)) {
            throw new InvalidArgumentException('Challenge nonce store must not be null');
        }
        if (is_null($this->secureRandom)) {
            throw new InvalidArgumentException('Secure random generator must not be null');
        }
        DateAndTime::requirePositiveDuration($this->ttlSeconds, 'Nonce TTL');
    }
}
