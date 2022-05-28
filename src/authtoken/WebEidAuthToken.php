<?php

/* The MIT License (MIT)
*
* Copyright (c) 2022 Petr Muzikant <pmuzikant@email.cz>
*
* > Permission is hereby granted, free of charge, to any person obtaining a copy
* > of this software and associated documentation files (the "Software"), to deal
* > in the Software without restriction, including without limitation the rights
* > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* > copies of the Software, and to permit persons to whom the Software is
* > furnished to do so, subject to the following conditions:
* >
* > The above copyright notice and this permission notice shall be included in
* > all copies or substantial portions of the Software.
* >
* > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* > THE SOFTWARE.
*/

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\authtoken;

use UnexpectedValueException;

/**
 * Object holder for authtoken values.
 */
class WebEidAuthToken
{
    private ?string $unverifiedCertificate = null;
    private ?string $signature = null;
    private ?string $algorithm = null;
    private ?string $format = null;

    /**
     * Constructs the token object from json string.
     *
     * @throws UnexpectedValueException some key in json is array or int
     *
     * @return null|void null in case of wrong json encoding
     */
    public function __construct(string $json)
    {
        // TODO: maybe use some library for json loading? however works fine right now
        // this constructing process is written in order to be compatible with tests
        // i.e. checking for array and integers
        $jsonDecoded = json_decode($json, true);
        $classAttritutes = get_class_vars(self::class);

        if (is_null($jsonDecoded)) {
            return null;
        }

        foreach ($classAttritutes as $key => $value) {
            if (key_exists($key, $jsonDecoded)) {
                $jsonValue = $jsonDecoded[$key];
                if (is_string($jsonValue)) {
                    $this->{$key} = $jsonValue;
                } elseif (is_array($jsonValue)) {
                    throw new UnexpectedValueException("'{$key}' is array, string expected");
                } elseif (is_int($jsonValue)) {
                    throw new UnexpectedValueException("'{$key}' is int, string expected");
                }
            }
        }
    }

    public function getUnverifiedCertificate(): ?string
    {
        return $this->unverifiedCertificate;
    }

    public function setUnverifiedCertificate(string $unverifiedCertificate): void
    {
        $this->unverifiedCertificate = $unverifiedCertificate;
    }

    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function getFormat(): ?string
    {
        return $this->format;
    }

    public function setFormat(string $format): void
    {
        $this->format = $format;
    }
}
