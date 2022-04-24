<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\authtoken;

use UnexpectedValueException;

class WebEidAuthToken
{
    private ?string $unverifiedCertificate = null;
    private ?string $signature = null;
    private ?string $algorithm = null;
    private ?string $format = null;

    public function __construct(string $json)
    {
        // TODO: maybe use some library for json loading?
        // this constructing process is written in order to be compatible with tests
        // i.e. checking for array
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
