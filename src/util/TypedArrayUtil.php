<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\util;

use ArrayAccess;
use ArrayIterator;
use BadMethodCallException;
use Countable;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use IteratorAggregate;
use muzosh\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidator;
use phpseclib3\File\X509;
use TypeError;

/* what is the best way of ensuring typed array in PHP?
    https://www.cloudsavvyit.com/10040/approaches-to-creating-typed-arrays-in-php/
    A) ignore and use regular arrays - not really solving the problem
    B) Variadic Arguments - only once per function
    C) Collection classes <== this code implements this option

    in needed more array functions, here is good example
    https://gist.github.com/MightyPork/5ad28f208f046a24831c
    */
abstract class TypedArray implements Countable, ArrayAccess, IteratorAggregate
{
    protected array $array;

    abstract public function __construct();

    // this method makes it possible to call array_XX PHP functions on this object,
    // but does not work with array_push, we it is not currently needed
    // public function __call($func, $argv)
    // {
    //     if (!is_callable($func) || 'array_' !== substr(strval($func), 0, 6)) {
    //         throw new BadMethodCallException(__CLASS__.'->'.$func);
    //     }

    //     return call_user_func_array($func, array_merge(array($this->array), $argv));
    // }

    public function count(): int
    {
        return count($this->array);
    }

    public function offsetExists($offset): bool
    {
        return isset($this->array[$offset]);
    }

    public function offsetGet($offset): mixed
    {
        return $this->array[$offset];
    }

    public function pushItem($value): void
    {
        $this->checkInstance($value);
        array_push($this->array, $value);
    }

    public function offsetUnset($offset): void
    {
        unset($this->array[$offset]);
    }

    public function offsetSet($offset, $value): void
    {
        $this->checkInstance($value);
        $this->array[$offset] = $value;
    }

    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->array);
    }

    abstract public function checkInstance($value): void;

    protected function makeUnique(): void
    {
        // SORT_REGULAR so it compares class attributes as arrays, not as strings
        $this->array = array_unique($this->array, SORT_REGULAR);
    }
}

final class SubjectCertificateValidatorArray extends TypedArray
{
    public function __construct(SubjectCertificateValidator ...$array)
    {
        $this->array = $array;
    }

    public function checkInstance($value): void
    {
        if (!$value instanceof SubjectCertificateValidator) {
            throw new TypeError('Can only insert '.SubjectCertificateValidator::class);
        }
    }
}

class X509Array extends TypedArray
{
    public function __construct(X509 ...$certificates)
    {
        $this->array = $certificates;
    }

    public function checkInstance($value): void
    {
        if (!$value instanceof X509) {
            throw new TypeError('Can only insert '.X509::class);
        }
    }

    // other functions call it with X509Array,
    // individual certificates are for logging
    public static function getSubjectDNs(?X509Array $x509array, X509 ...$certificates): array
    {
        $array = is_null($x509array) ? $certificates : $x509array;
        $subjectDNs = array();
        foreach ($array as $certificate) {
            $subjectDNs[] = $certificate->getSubjectDN(X509::DN_STRING);
        }

        return $subjectDNs;
    }
}

final class X509UniqueArray extends X509Array
{
    public function __construct(X509 ...$certificates)
    {
        parent::__construct(...$certificates);
        $this->makeUnique();
    }

    // override this so we can check for uniqueness when assigning new value
    public function offsetSet($offset, $value): void
    {
        $this->checkInstance($value);

        if (in_array($value, $this->array, true)) {
            // maybe do nothing instead of throwing exception? depends on function usage
            throw new InvalidArgumentException('This object already is in the array.');
        }

        $this->array[$offset] = $value;
    }
}

final class UriUniqueArray extends TypedArray
{
    public function __construct(Uri ...$urls)
    {
        $this->array = $urls;
        $this->makeUnique();
    }

    public function checkInstance($value): void
    {
        if (!$value instanceof Uri) {
            throw new \TypeError('Can only insert '.Uri::class);
        }
    }

    // override this so we can check for uniqueness when assigning new value
    public function offsetSet($offset, $value): void
    {
        $this->checkInstance($value);

        if (in_array($value, $this->array, true)) {
            // maybe do nothing instead of throwing exception? depends on function usage
            throw new InvalidArgumentException('This object already is in the array.');
        }

        $this->array[$offset] = $value;
    }

    public function inArray(Uri $uri): bool
    {
        return in_array($uri, $this->array);
    }

    public function getUrls(): array
    {
        $return = array();
        foreach ($this->array as $uri) {
            $return[] = strval($uri);
        }

        return $return;
    }
}
