<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp\service;

/**
 * An OCSP service that uses a single designated OCSP responder.
 */
class DesignatedOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final DesignatedOcspServiceConfiguration configuration;

    public DesignatedOcspService(DesignatedOcspServiceConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    @Override
    public boolean doesSupportNonce() {
        return configuration.doesSupportNonce();
    }

    @Override
    public URI getAccessLocation() {
        return configuration.getOcspServiceAccessLocation();
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date producedAt) throws AuthTokenException {
        try {
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!configuration.getResponderCertificate().equals(responderCertificate)) {
                throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                    "the configured designated OCSP responder certificate");
            }
            certificateIsValidOnDate(responderCertificate, producedAt, "Designated OCSP responder");
        } catch (CertificateException e) {
            throw new OCSPCertificateException("X509CertificateHolder conversion to X509Certificate failed");
        }
    }

    public boolean supportsIssuerOf(X509Certificate certificate) throws CertificateEncodingException {
        return configuration.supportsIssuerOf(certificate);
    }

}
