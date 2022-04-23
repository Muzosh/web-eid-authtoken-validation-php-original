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
        foreach (json_decode($json, true) ?? array('json_decode_error' => '') as $key => $value) {
            if (property_exists(__CLASS__, $key)) {
                $this->{$key} = $value;
            } else {
                throw new UnexpectedValueException('Unknown WebEidAuthToken key: '.$key);
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
