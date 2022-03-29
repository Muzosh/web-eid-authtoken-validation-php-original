<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\authtoken;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

# TODO: find out where is this parsed from json and how to define ignoring unknown values
@JsonIgnoreProperties(ignoreUnknown = true)
class WebEidAuthToken {

    private string $unverifiedCertificate;
    private string $signature;
    private string $algorithm;
    private string $format;

    public function getUnverifiedCertificate() : string {
        return unverifiedCertificate;
    }

    public function setUnverifiedCertificate(string $unverifiedCertificate) : void {
        $this->$unverifiedCertificate = $unverifiedCertificate;
    }

    public function getSignature() : string {
        return $this->$signature;
    }

    public function setSignature(string $signature) : void {
        $this->$signature = $signature;
    }

    public function getAlgorithm() : string {
        return $this->$algorithm;
    }

    public function setAlgorithm(string $algorithm) : void {
        $this->$algorithm = $algorithm;
    }

    public function getFormat() : string {
        return $this->$format;
    }

    public function setFormat(string $format) : void {
        $this->$format = $format;
    }

}
