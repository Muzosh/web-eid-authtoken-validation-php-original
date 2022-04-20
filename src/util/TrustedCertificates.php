<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use Countable;

// CertStore + TrustedAnchors in Java vs TrustedCertificates in C#
final class CertStore
{
    private X509Array $certificates;
    private array $CRLs;

    public function __construct(array $certificates, array $CRLs = null)
    {
        $this->certificates = new X509Array(...$certificates);
        $this->CRLs = $CRLs ?? array();
    }

    public function getCertificates(): X509Array
    {
        return $this->certificates;
    }

    public function getCRLs(): array
    {
        return $this->CRLs;
    }
}

// TODO: can be changed for define(currentClass::class . "CONST_NAME", EXPRESSION)
// for nonmalluable variable
final class TrustedAnchors implements Countable
{
    private X509UniqueArray $certificates;

    public function __construct(array $certificates)
    {
        $this->certificates = new X509UniqueArray(...$certificates);
    }

    public function count(): int
    {
        return count($this->certificates);
    }

    public function getCertificates(): X509UniqueArray
    {
        return $this->certificates;
    }
}
