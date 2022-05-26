<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use Countable;

// can be maybe changed for define(currentClass::class . "CONST_NAME", EXPRESSION) for nonmalluable variable instead of object with private property?
// currently it works fine with this object, no need to define it as constant
final class TrustedCertificates implements Countable
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
