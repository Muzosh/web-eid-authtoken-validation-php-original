<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

/**
 * This is a simplified version of Bouncy Castle's {@link OCSPReqBuilder}.
 *
 * @see OCSPReqBuilder
 */
final class OcspRequestBuilder {

    private static final SecureRandom GENERATOR = new SecureRandom();

    private $ocspNonceEnabled = true;
    private $certificateId;

    public function withCertificateId(CertificateID $certificateId):OcspRequestBuilder {
        $this->certificateId = $certificateId;
        return $this;
    }

    public function enableOcspNonce(bool $ocspNonceEnabled):OcspRequestBuilder {
        this.ocspNonceEnabled = ocspNonceEnabled;
        return this;
    }

    /**
     * The returned {@link OCSPReq} is not re-usable/cacheable. It contains a one-time nonce
     * and responders will reject subsequent requests that have the same nonce value.
     */
    public function build():OCSPReq {
        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(Objects.requireNonNull(certificateId, "certificateId"));

        if (ocspNonceEnabled) {
            addNonce(builder);
        }

        return builder.build();
    }

    private function addNonce(OCSPReqBuilder $builder):void {
        final byte[] nonce = new byte[8];
        GENERATOR.nextBytes(nonce);

        final Extension[] extensions = new Extension[]{
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce))
        };
        builder.setRequestExtensions(new Extensions(extensions));
    }

}
