<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;
use Monolog\Logger;
use muzosh\web_eid_authtoken_validation_php\util\WebEidLogger;
use RuntimeException;
use UnexpectedValueException;

class OcspClientOpenSSlImpl implements OcspClient
{
    private Logger $logger;

    private function __construct(int $ocspRequestTimeoutSeconds)
    {
        $this->logger = WebEidLogger::getLogger(OcspClientOpenSSlImpl::class);
    }

    public function request(Uri $uri, string $encodedOcspRequest): string
    {
        $request = new Request('POST', $uri, array(
            'Content-Type' => OcspClientOpenSSlImpl::OCSP_REQUEST_TYPE,
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

        if (empty($contentType) || false === strpos($contentType[0], OcspClientOpenSSlImpl::OCSP_RESPONSE_TYPE)) {
            throw new UnexpectedValueException('OCSP response content type is not '.OcspClientOpenSSlImpl::OCSP_RESPONSE_TYPE);
        }

        return $response->getBody()->getContents();
    }
}
