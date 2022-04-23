<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the challenge nonce was not found in the nonce store.
 */
class ChallengeNonceNotFoundException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct('Challenge nonce was not found in the nonce store');
    }
}
