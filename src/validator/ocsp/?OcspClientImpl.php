<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\validator\ocsp;

class OcspClientImpl implements OcspClient {

    private static final Logger LOG = LoggerFactory.getLogger(OcspClientImpl.class);
    private static final MediaType OCSP_REQUEST_TYPE = MediaType.get("application/ocsp-request");
    private static final MediaType OCSP_RESPONSE_TYPE = MediaType.get("application/ocsp-response");

    private $httpClient;

    public static function build(DateTimeInterval $ocspRequestTimeout):OcspClient {
        return new OcspClientImpl(
            new OkHttpClient.Builder()
                .connectTimeout(ocspRequestTimeout)
                .callTimeout(ocspRequestTimeout)
                .build()
        );
    }

    /**
     * Use OkHttpClient to fetch the OCSP response from the OCSP responder service.
     *
     * @param uri        OCSP server URL
     * @param ocspReq    OCSP request
     * @return OCSP response from the server
     * @throws IOException if the request could not be executed due to cancellation, a connectivity problem or timeout,
     *                     or if the response status is not successful, or if response has wrong content type.
     */
    public function request(array $uri, OCSPReq $ocspReq):OCSPResp {
        final RequestBody requestBody = RequestBody.create(ocspReq.getEncoded(), OCSP_REQUEST_TYPE);
        final Request request = new Request.Builder()
            .url(uri.toURL())
            .post(requestBody)
            .build();

        try (final Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("OCSP request was not successful, response: " + response);
            } else {
                LOG.debug("OCSP response: {}", response);
            }
            try (final ResponseBody responseBody = Objects.requireNonNull(response.body(), "response body")) {
                Objects.requireNonNull(responseBody.contentType(), "response content type");
                if (!OCSP_RESPONSE_TYPE.type().equals(responseBody.contentType().type()) ||
                    !OCSP_RESPONSE_TYPE.subtype().equals(responseBody.contentType().subtype())) {
                    throw new IOException("OCSP response content type is not " + OCSP_RESPONSE_TYPE);
                }
                return new OCSPResp(responseBody.bytes());
            }
        }
    }

    private function __construct(OkHttpClient $httpClient) {
        $this->httpClient = $httpClient;
    }

}
