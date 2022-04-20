<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\RequestOptions;
use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use RuntimeException;
use UnexpectedValueException;

class OcspClientHTTPImpl implements OcspClient
{
    private const OCSP_REQUEST_TYPE = 'application/ocsp-request';
    private const OCSP_RESPONSE_TYPE = 'application/ocsp-response';

    private Logger $logger;

    private Client $httpClient;

    private function __construct(Client $httpClient)
    {
        $this->logger = WebEidLogger::getLogger(OcspClientHTTPImpl::class);
        $this->httpClient = $httpClient;
    }

    public static function build(int $ocspRequestTimeoutSeconds): OcspClient
    {
        return new OcspClientHTTPImpl(
            new Client(array(
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::CONNECT_TIMEOUT => (float) $ocspRequestTimeoutSeconds,
                RequestOptions::TIMEOUT => (float) $ocspRequestTimeoutSeconds,
            ))
        );
    }

    public function request(Uri $uri, string $encodedOcspRequest): string
    {
        $request = new Request('POST', $uri, array(
            'Content-Type' => OcspClientHTTPImpl::OCSP_REQUEST_TYPE,
            'charset' => 'utf-8',
        ), $encodedOcspRequest);

        try {
            $response = $this->httpClient->send($request);
        } catch (RequestException $e) {
            throw new RuntimeException('OCSP request was not successful.', -1, $e);
        }

        $statusCode = $response->getStatusCode();

        if ($statusCode < 200 && $statusCode > 299) {
            throw new UnexpectedValueException('OCSP request was not successful, response: http/'.$response->getProtocolVersion().' - '.$statusCode.' - '.$response->getReasonPhrase().' - '.$request->getUri());
        }

        $this->logger->debug('OCSP response: http/'.$response->getProtocolVersion().' - '.$statusCode.' - '.$response->getReasonPhrase().' - '.$request->getUri());

        $contentType = $response->getHeader('Content-Type');

        if (empty($contentType) || false === strpos($contentType[0], OcspClientHTTPImpl::OCSP_RESPONSE_TYPE)) {
            throw new UnexpectedValueException('OCSP response content type is not '.OcspClientHTTPImpl::OCSP_RESPONSE_TYPE);
        }

        return $response->getBody()->getContents();
    }
}
