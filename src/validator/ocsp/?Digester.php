<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

/**
 * BouncyCastle's OCSPReqBuilder needs a DigestCalculator but BC doesn't
 * provide any public implementations of that interface. That's why we need to
 * write our own. There's a default SHA-1 implementation and one for SHA-256.
 * Which one to use will depend on the Certificate Authority (CA).
 */
final class Digester implements DigestCalculator {

    private $dos;
    private $algId;

    public static function sha1(): DigestCalculator {
        $digest = new SHA1Digest();
        $algId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);

        return new Digester(digest, algId);
    }

    public static function sha256():DigestCalculator {
        $digest = new SHA256Digest();

        // The OID for SHA-256: http://www.oid-info.com/get/2.16.840.1.101.3.4.2.1
        $oid = "2.16.840.1.101.3.4.2.1";
        $algId = new AlgorithmIdentifier(oid);

        return new Digester(digest, algId);
    }

    private function __construct(Digest $digest, AlgorithmIdentifier $algId) {
        $this->dos = new DigestOutputStream($digest);
        $this->algId = $algId;
    }

    public function getAlgorithmIdentifier():AlgorithmIdentifier {
        return $this->algId;
    }

    public function getOutputStream():OutputStream {
        return $this->dos;
    }

    public function getDigest(): array {
        return $this->dos->getDigest();
    }
}
