<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use InvalidArgumentException;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspRequestObject;

final class OcspRequestBuilder
{
    private $secureRandom;

    private bool $ocspNonceEnabled = true;
    private array $certificateIdMapped;

    public function __construct()
    {
        $this->secureRandom = function ($nonce_length): string {
            return random_bytes($nonce_length);
        };
    }

    public function withCertificateId(array $certificateIdMapped): OcspRequestBuilder
    {
        $this->certificateIdMapped = $certificateIdMapped;

        return $this;
    }

    public function enableOcspNonce(bool $ocspNonceEnabled): OcspRequestBuilder
    {
        $this->ocspNonceEnabled = $ocspNonceEnabled;

        return $this;
    }

    public function build(): OcspRequestObject
    {
        $ocspRequest = new OcspRequestObject();

        if (!isset($this->certificateIdMapped)) {
            throw new InvalidArgumentException('CertificateId is not set. withCertificateId() should have been called before build().');
        }

        $ocspRequest->addRequest($this->certificateIdMapped);

        if ($this->ocspNonceEnabled) {
            $nonceBytes = call_user_func($this->secureRandom, 8);
            $ocspRequest->addNonceExtension($nonceBytes);
        }

        return $ocspRequest;
    }
}
