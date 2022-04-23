<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\challenge;

use DateTime;

class ChallengeNonce
{
    private string $base64EncodedNonce;
    private DateTime $expirationTime;

    public function __construct(string $base64EncodedNonce, DateTime $expirationTime)
    {
        $this->base64EncodedNonce = $base64EncodedNonce;
        $this->expirationTime = $expirationTime;
    }

    public function getBase64EncodedNonce():string
    {
        return $this->base64EncodedNonce;
    }

    public function getExpirationTime():DateTime
    {
        return $this->expirationTime;
    }
}
