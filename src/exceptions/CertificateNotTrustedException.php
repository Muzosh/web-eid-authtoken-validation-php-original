<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\exceptions;

use \Throwable;
use \OpenSSLCertificate;

/**
 * Thrown when the given certificate is not signed by a trusted CA.
 */
class CertificateNotTrustedException extends AuthTokenException {

	# TODO: figure out how to get subject from OpenSSLCertificate
	# is it even good idea to use this when OpenSSLCertificate object requires PHP 8.0.0?
	public function __construct(OpenSSLCertificate $x509certificate, Throwable $cause)
	{
		parent::__construct("Certificate " +  + " is not trusted", $cause);
	}

	public CertificateNotTrustedException(X509Certificate certificate, Throwable e) {
        super("Certificate " + certificate.getSubjectDN() + " is not trusted", e);
    }
}
