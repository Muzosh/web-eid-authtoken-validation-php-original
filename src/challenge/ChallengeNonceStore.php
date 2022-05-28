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

use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use muzosh\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use muzosh\web_eid_authtoken_validation_php\util\DateAndTime;

/**
 * An abstract class for storing generated challenge nonces and accessing their generation time.
 * External application must implement this class based on available technologies for persistent store.
 */
abstract class ChallengeNonceStore
{
    /**
     * Store challenge nonce.
     */
    abstract public function put(ChallengeNonce $challengeNonce): void;

    /**
	 * This function should be used by external application to get and remove challenge nonce.\
	 * The implementation of removing nonce from store should be in getAndRemoveImpl
     * @throws ChallengeNonceNotFoundException
     * @throws ChallengeNonceExpiredException
     */
    final public function getAndRemove(): ChallengeNonce
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

	/**
	 * Get and remove current challenge nonce for validation.
	 * @return null|ChallengeNonce return null if challenge nonce was not found or there was other error
	 */
    abstract protected function getAndRemoveImpl(): ?ChallengeNonce;
}
