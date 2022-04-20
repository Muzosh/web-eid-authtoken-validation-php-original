<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

final class OcspRequestBuilder
{
    private $secureRandom;

    private bool $ocspNonceEnabled = true;
    private string $encodedCertificateId;

    public function withCertificateId(string $certificateId): OcspRequestBuilder
    {
        $this->certificateId = $certificateId;

        return $this;
    }

    public function enableOcspNonce(bool $ocspNonceEnabled): OcspRequestBuilder
    {
        $this->ocspNonceEnabled = $ocspNonceEnabled;

        return $this;
    }

    /**
     * The returned request is not re-usable/cacheable. It contains a one-time nonce
     * and responders will reject subsequent requests that have the same nonce value.
     */
    public function build()
    {
        $secureRandom = function ($nonce_length) {
            return unpack('c*', random_bytes($nonce_length));
        };
    }

    private function addNonce(): void
    {
    }
}
