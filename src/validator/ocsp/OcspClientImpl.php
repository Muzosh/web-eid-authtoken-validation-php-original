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

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\RequestOptions;
use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use muzosh\web_eid_authtoken_validation_php\ocsp\OcspResponseObject;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;

class OcspClientImpl implements OcspClient
{
    private const OCSP_REQUEST_TYPE = 'application/ocsp-request';
    private const OCSP_RESPONSE_TYPE = 'application/ocsp-response';

    private Logger $logger;

    private Client $httpClient;

    private function __construct(Client $httpClient)
    {
        $this->logger = WebEidLogger::getLogger(self::class);
        $this->httpClient = $httpClient;
    }

    public static function build(int $ocspRequestTimeoutSeconds): OcspClient
    {
        // build new OcspClientImpl with GuzzleHttp\Client
        return new OcspClientImpl(
            new Client(array(
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::CONNECT_TIMEOUT => (float) $ocspRequestTimeoutSeconds,
                RequestOptions::TIMEOUT => (float) $ocspRequestTimeoutSeconds,
            ))
        );
    }

    public function request(Uri $uri, string $encodedOcspRequest): OcspResponseObject
    {
        // create new request
        $request = new Request(
            'POST',
            $uri,
            // headers
            array(
                'Content-Type' => self::OCSP_REQUEST_TYPE,
                'charset' => 'utf-8',
            ),
            $encodedOcspRequest
        );

        // send and get response
        $response = $this->httpClient->send($request);

        // check status code
        $statusCode = $response->getStatusCode();
        if ($statusCode < 200 && $statusCode > 299) {
            throw new UserCertificateOCSPCheckFailedException('OCSP request was not successful, response: http/'.$response->getProtocolVersion().' - '.$statusCode.' - '.$response->getReasonPhrase().' - '.$request->getUri());
        }

        $this->logger->debug('OCSP response: http/'.$response->getProtocolVersion().' - '.$statusCode.' - '.$response->getReasonPhrase().' - '.$request->getUri());

        // check header
        $contentType = $response->getHeader('Content-Type');
        if (empty($contentType) || false === strpos($contentType[0], self::OCSP_RESPONSE_TYPE)) {
            throw new UserCertificateOCSPCheckFailedException('OCSP response content type is not '.self::OCSP_RESPONSE_TYPE);
        }

        // get new OcspResponseObject from encoded DER
        return new OcspResponseObject($response->getBody()->getContents());
    }
}
