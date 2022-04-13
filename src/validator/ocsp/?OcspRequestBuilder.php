<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * This is a simplified version of Bouncy Castle's {@link OCSPReqBuilder}.
 *
 * @see OCSPReqBuilder
 */
public final class OcspRequestBuilder {

    private static final SecureRandom GENERATOR = new SecureRandom();

    private boolean ocspNonceEnabled = true;
    private CertificateID certificateId;

    public OcspRequestBuilder withCertificateId(CertificateID certificateId) {
        this.certificateId = certificateId;
        return this;
    }

    public OcspRequestBuilder enableOcspNonce(boolean ocspNonceEnabled) {
        this.ocspNonceEnabled = ocspNonceEnabled;
        return this;
    }

    /**
     * The returned {@link OCSPReq} is not re-usable/cacheable. It contains a one-time nonce
     * and responders will reject subsequent requests that have the same nonce value.
     */
    public OCSPReq build() throws OCSPException {
        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(Objects.requireNonNull(certificateId, "certificateId"));

        if (ocspNonceEnabled) {
            addNonce(builder);
        }

        return builder.build();
    }

    private void addNonce(OCSPReqBuilder builder) {
        final byte[] nonce = new byte[8];
        GENERATOR.nextBytes(nonce);

        final Extension[] extensions = new Extension[]{
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce))
        };
        builder.setRequestExtensions(new Extensions(extensions));
    }

}
