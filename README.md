# web-eid-authtoken-validation-php

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Total Downloads][ico-downloads]][link-downloads]

> *web-eid-authtoken-validation-php* is a PHP library for issuing challenge nonces and validating Web eID authentication tokens during secure authentication with electronic ID (supported state-issued or custom built) smart cards in web applications.

> This is a sibling repository [for web-eid-authtoken-validation-java](https://github.com/web-eid/web-eid-authtoken-validation-java). More information about the Web eID project is available on the project [website](https://web-eid.eu/).

## TL;DR

- PHP library used for validating [Web-eID](https://github.com/web-eid) token
    - follows same principles and functionality as existing [java](https://github.com/web-eid/web-eid-authtoken-validation-java) and [.net](https://github.com/web-eid/web-eid-authtoken-validation-dotnet) validation libraries
    - however in PHP there is no bouncy-castle, which is heavily used in existing libraries
    - most stuff (working with certificates, keys, cryptography, etc.) is replicated with [phpseclib](https://phpseclib.com/) library + OCSP request and response handling (creation, verification, etc.) is developed from scratch
- code-base details:
    - all unit-tests (with mocked certificates and tokens) ported from java library are functional
    - works with test EstEID from SK ID Solutions without problems
    - has the same functionality as other (Java and .NET) validation libraries

## Nextcloud App implementation

Example implementation and also usable two-factor authentication Nextcloud App (module) can be found in [twofactor_nextcloud](https://github.com/Muzosh/twofactor_webeid).

## Don't have official state-issued card supported by Web-eID? Create your own!

For implementing this library with self-built/personalised/custom JavaCard, check out [InfinitEID](https://github.com/Muzosh/InfinitEID). You will also need a tweaked Web-eID native application, details are in [libelectronic-id-with-InfinitEID](https://github.com/Muzosh/libelectronic-id-with-InfinitEID).

# Table of contents

- [web-eid-authtoken-validation-php](#web-eid-authtoken-validation-php)
	- [TL;DR](#tldr)
	- [Nextcloud App implementation](#nextcloud-app-implementation)
	- [Custom JavaCards](#custom-javacards)
- [Table of contents](#table-of-contents)
- [Quickstart](#quickstart)
	- [1. Initialize library (INSTALLATION)](#1-initialize-library-installation)
		- [Add the library to your project](#add-the-library-to-your-project)
		- [Prepare OIDs](#prepare-oids)
		- [Configure library](#configure-library)
	- [2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)
	- [3. Configure the challenge nonce generator](#3-configure-the-challenge-nonce-generator)
	- [4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)
	- [5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)
	- [6. Make sure that challenge nonces are correctly issued](#6-make-sure-that-challenge-nonces-are-correctly-issued)
	- [7. Implement frontend to obtain authtoken](#7-implement-frontend-to-obtain-authtoken)
	- [8. Validate the token and obtain authenticatin result](#8-validate-the-token-and-obtain-authenticatin-result)
- [Introduction](#introduction)
- [Authentication token format](#authentication-token-format)
- [Authentication token validation](#authentication-token-validation)
	- [Basic usage](#basic-usage)
	- [Extended configuration](#extended-configuration)
		- [Certificates' *Authority Information Access* (AIA) extension](#certificates-authority-information-access-aia-extension)
	- [Possible validation errors](#possible-validation-errors)
	- [Stateful and stateless authentication](#stateful-and-stateless-authentication)
- [Challenge nonce generation](#challenge-nonce-generation)
	- [Basic usage](#basic-usage-1)
	- [Extended configuration](#extended-configuration-1)
- [Change log](#change-log)
- [Testing](#testing)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#credits)
- [License](#license)

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your PHP web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

A PHP web application that uses Composer to manage packages is needed for running this quickstart.

In the following example we are using the [Nextcloud Application](https://docs.nextcloud.com/server/latest/developer_manual/), but the examples can be easily ported to other PHP web application frameworks.

See the full example [here](https://github.com/Muzosh/nextcloud_twofactor_webeid).

## 1. Initialize library (INSTALLATION)

### Add the library to your project

Add the following lines to `composer.json` to include the Web eID authentication token validation library in your project:

```json
"repositories": [
 {
  "type": "vcs",
  "url": "https://github.com/Muzosh/web-eid-authtoken-validation-php"
 }
],
"require": {
 "muzosh/web_eid_authtoken_validation_php": "dev-main"
},
```

Then, run appropriate composer command `composer install`/`composer update` to install the package into the `vendor/` directory. Include composer `autoload.php` file and you are ready to use classes from this library.

### Prepare OIDs

To properly handle the ASN1 encoding/decoding, run `ASN1Util::loadOIDs();` at the start of any HTTP request, which requires this library.

```php
public function register(IRegistrationContext $context): void {
  require_once __DIR__.'/../../vendor/autoload.php';
  ASN1Util::loadOIDs();
 }
```

### Configure library

Configure values in [Config.php](config/Config.php) file for log path and nonce length.

```php
// Config helpers
$current_directory = dirname(__FILE__);
$root_diretory = dirname($current_directory);

// Config
define('CONFIG', array(
    'log_file_path' => $root_diretory.'/web-eid-authtoken-validation-php.log',
 'nonce_length' => 32
));
```

## 2. Configure the challenge nonce store

The validation library needs a store for saving the issued challenge nonces. As it must be guaranteed that the authentication token is received from the same browser to which the corresponding challenge nonce was issued, using a session-backed challenge nonce store is the most natural choice.

Implement the session-backed challenge nonce store as follows:

```php
<?php

declare(strict_types=1);

namespace OCA\TwoFactorWebEid\Service;

use DateTime;
use muzosh\web_eid_authtoken_validation_php\challenge\ChallengeNonce;
use muzosh\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;
use OCP\ISession;

class SessionBackedChallengeNonceStore extends ChallengeNonceStore {
 private const CHALLENGE_NONCE_KEY = 'web-eid-challenge-nonce';
 private $session;

 public function __construct(ISession $session) {
  $this->session = $session;
 }

 public function put(ChallengeNonce $challengeNonce): void {
  $this->session[self::CHALLENGE_NONCE_KEY] = serialize($challengeNonce);
 }

 protected function getAndRemoveImpl(): ?ChallengeNonce {
  if (!$this->session[self::CHALLENGE_NONCE_KEY]) {
   return null;
  }
  
  $challengeNonce = unserialize($this->session[self::CHALLENGE_NONCE_KEY], array(
   'allowed_classes' => array(ChallengeNonce::class, DateTime::class),
  ));

  if (!$challengeNonce) {
   return null;
  }

  unset($this->session[self::CHALLENGE_NONCE_KEY]);

  return $challengeNonce;
 }
}
```

## 3. Configure the challenge nonce generator

The validation library needs to generate authentication challenge nonces and store them for later validation in the challenge nonce store. Overview of challenge nonce usage is provided in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The challenge nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the challenge nonce generator as follows:

```php
use muzosh\web_eid_authtoken_validation_php\challenge\ChallengeNonceGenerator;
use muzosh\web_eid_authtoken_validation_php\challenge\ChallengeNonceGeneratorBuilder;
use muzosh\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;

...
public function getGenerator(ChallengeNonceStore $challengeNonceStore): ChallengeNonceGenerator {
  return (new ChallengeNonceGeneratorBuilder())
   ->withNonceTtl($this->config['CHALLENGE_NONCE_TTL_SECONDS']) // 300
   ->withChallengeNonceStore($challengeNonceStore)
   ->build()
  ;
 }
...
```

## 4. Add trusted certificate authority certificates

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication and OCSP responder certificates.

First, copy the trusted certificates, for example `ESTEID-SK_2015.cer` and `ESTEID2018.cer`, to `trustedcerts/`, then load the certificates as follows:

```php
use muzosh\web_eid_authtoken_validation_php\certificate\CertificateLoader;

...
 public function loadTrustedCACertificatesFromCertFiles(): array {
  $pathnames = array_map(
   'basename',
   glob(
    $this->config['TRUSTED_CERT_PATH'].'/*.{crt,cer,pem,der}', // __DIR__.'/../../trustedcerts'
    GLOB_BRACE
   )
  );

  return CertificateLoader::loadCertificatesFromPath(
   $this->config['TRUSTED_CERT_PATH'], // __DIR__.'/../../trustedcerts'
   ...$pathnames
   );
 }
...
```

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The mandatory parameters are the website origin (the URL serving the web application, see section [*Basic usage*](#basic-usage) below) and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

```php
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use muzosh\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;

...
public function getValidator(): AuthTokenValidator {
  return (new AuthTokenValidatorBuilder())
   ->withSiteOrigin(new Uri($this->config['ORIGIN'])) // 'https://'.$_SERVER['SERVER_ADDR']
   ->withTrustedCertificateAuthorities(...self::loadTrustedCACertificatesFromCertFiles())
   ->withoutUserCertificateRevocationCheckWithOcsp()
   ->build()
  ;
 }
...
```

## 6. Make sure that challenge nonces are correctly issued

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

Another option is to provide challenge nonce on page load, but make sure it is issued once per 1 request.

In the following example, we are using the getTemplate function for [2FA IProvider implementation](https://docs.nextcloud.com/server/latest/developer_manual/digging_deeper/two-factor-provider.html) to obtain the template and issue a challenge nonce at the same time.

```php
/**
  * Get the template for rending the 2FA provider view.
  */
 public function getTemplate(IUser $user): Template {
  $generator = $this->webEidService->getGenerator(
   $this->webEidService->getSessionBasedChallengeNonceStore()
  );
  $challengeNonce = $generator->generateAndStoreNonce();

  $template = new Template(Application::APP_NAME, 'WebEidChallenge');
  $template->append('nonce', $challengeNonce->getBase64EncodedNonce()); // challenge is appended to HTML hidden input

  return $template;
 }
```

Also, see general guidelines for implementing secure authentication services [here](https://github.com/SK-EID/smart-id-documentation/wiki/Secure-Implementation-Guide).

## 7. Implement frontend to obtain authtoken

The javascript front end should call `authenticate()` method of `webeid` object from [here](https://github.com/web-eid/web-eid.js).

Make sure the result from this method safely reaches backend application, where you can validate the authtoken.

In the Nextcloud example application, the JSON token is assigned to a another hidden input, which is part of a Nextcloud 2FA form authentication.

```javascript
submitButton.addEventListener("click", async () => {
  try {
   showSpinner();
   hideError();
   const authToken = await webeid.authenticate(nonce, lang);
   document.querySelector("#webeid-token").value =
    JSON.stringify(authToken);
   form.submit();
  } catch (error) {
   ...
  }
```

## 8. Validate the token and obtain authenticatin result

Authentication consists of calling the `validate()` method of the authentication token validator. The internal implementation of the validation process is described in more detail below and in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

The identity of authenticated user can be obtained from card's certificate.

Nextcloud example:

```php
...
// WebEidProvider
public function verifyChallenge(IUser $user, $challenge): bool {
  try {
   $challengeNonce = $this->webEidService->getSessionBasedChallengeNonceStore()->getAndRemove();
   try {
    $cert = $this->webEidService->getValidator()->validate(
     new WebEidAuthToken($challenge),
     $challengeNonce->getBase64EncodedNonce()
    );

    return $this->webEidService->authenticate($cert, $user);
   } catch (AuthTokenException $e) {
    $this->logger->error('WebEid authtoken validation unsuccessful: '.$e->getMessage(), $e->getTrace());
   }
  } catch (ChallengeNonceNotFoundException $e) {
   $this->logger->error('WebEid challenge not found: '.$e->getMessage(), $e->getTrace());
  } catch (ChallengeNonceExpiredException $e) {
   $this->logger->error('WebEid challenge nonce expired: '.$e->getMessage(), $e->getTrace());
  }

  return false;
 }
 ...

// WebEidService
public function authenticate(X509 $cert, IUser $user): bool {
  $certCN = CertificateData::getSubjectCN($cert);

  if ($user->getUID() == $certCN) {
   return true;
  }

  $this->logger->error(
   'WebEid authtoken validation successful, but CommonName does not match. UserID: '.
   $user->getUID().
   ', CN: '.
   $certCN
  );

  return false;
 }
```

# Introduction

The Web eID authentication token validation library for PHP contains the implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, authentication token format, validation requirements and challenge nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

# Authentication token format

In the following,

- **origin** is defined as the website origin, the URL serving the web application,
- **challenge nonce** (or challenge) is defined as a cryptographic nonce, a large random number that can be used only once, with at least 256 bits of entropy.

The Web eID authentication token is a JSON data structure that looks like the following example:

```json
{
  "unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4...",
  "algorithm": "RS256",
  "signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZha...",
  "format": "web-eid:1.0",
  "appVersion": "https://web-eid.eu/web-eid-app/releases/v2.0.0"
}
```

It contains the following fields:

- `unverifiedCertificate`: the base64-encoded DER-encoded authentication certificate of the eID user; the public key contained in this certificate should be used to verify the signature; the certificate cannot be trusted as it is received from client side and the client can submit a malicious certificate; to establish trust, it must be verified that the certificate is signed by a trusted certificate authority,

- `algorithm`: the signature algorithm used to produce the signature; the allowed values are the algorithms specified in [JWA RFC](https://www.ietf.org/rfc/rfc7518.html) sections 3.3, 3.4 and 3.5:

    ```
      "ES256", "ES384", "ES512", // ECDSA
      "PS256", "PS384", "PS512", // RSASSA-PSS
      "RS256", "RS384", "RS512"  // RSASSA-PKCS1-v1_5
    ```

- `signature`: the base64-encoded signature of the token (see the description below),

- `format`: the type identifier and version of the token format separated by a colon character '`:`', `web-eid:1.0` as of now; the version number consists of the major and minor number separated by a dot, major version changes are incompatible with previous versions, minor version changes are backwards-compatible within the given major version,

- `appVersion`: the URL identifying the name and version of the application that issued the token; informative purpose, can be used to identify the affected application in case of faulty tokens.

The value that is signed by the user’s authentication private key and included in the `signature` field is `hash(origin)+hash(challenge)`. The hash function is used before concatenation to ensure field separation as the hash of a value is guaranteed to have a fixed length. Otherwise the origin `example.com` with challenge nonce `.eu1234` and another origin `example.com.eu` with challenge nonce `1234` would result in the same value after concatenation. The hash function `hash` is the same hash function that is used in the signature algorithm, for example SHA256 in case of RS256.

# Authentication token validation

The authentication token validation process consists of two stages:

- First, **user certificate validation**: the validator parses the token and extracts the user certificate from the *unverifiedCertificate* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, **token signature validation**: the validator validates that the token signature was created using the provided user certificate by reconstructing the signed data `hash(origin)+hash(challenge)` and using the public key from the certificate to verify the signature in the `signature` field. If the signature verification succeeds, then the origin and challenge nonce have been implicitly and correctly verified without the need to implement any additional security checks.

The website back end must lookup the challenge nonce from its local store using an identifier specific to the browser session, to guarantee that the authentication token was received from the same browser to which the corresponding challenge nonce was issued. The website back end must guarantee that the challenge nonce lifetime is limited and that its expiration is checked, and that it can be used only once by removing it from the store during validation.

## Basic usage

As described in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*, the mandatory authentication token validator configuration parameters are the website origin and trusted certificate authorities.

**Origin** must be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components. Note that the `origin` URL must not end with a slash `/`.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token and the OCSP responder certificate is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be removed. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

Before validation, the previously issued **challenge nonce** must be looked up from the store using an identifier specific to the browser session. The challenge nonce must be passed to the `validate()` method in the corresponding parameter. Setting up the challenge nonce store is described in more detail in section *[2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)*.

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```php
$challengeNonce = getSessionBasedChallengeNonceStore()->getAndRemove()->getBase64EncodedNonce();
$token = new WebEidAuthToken($tokenString);
$cert = getValidator()->validate($token,$challengeNonce);
```

The `validate()` method returns the validated user certificate object if validation is successful or throws an exception as described in section *[Possible validation errors](#possible-validation-errors)* below if validation fails. The `CertificateData` and `TitleCase` classes can be used for extracting user information from the user certificate object:

```php  
$certCN = CertificateData::getSubjectCN($cert); // testuser

if ($user->getUID() == $certCN) {
 return true;
}
```

## Extended configuration  

The following additional configuration options are available in `AuthTokenValidatorBuilder`:  

- `withoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. OCSP check is enabled by default and the OCSP responder access location URL is extracted from the user certificate AIA extension unless a designated OCSP service is activated.
- `withDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration)` – activates the provided designated OCSP responder service configuration for user certificate revocation check with OCSP. The designated service is only used for checking the status of the certificates whose issuers are supported by the service, for other certificates the default AIA extension service access location will be used. See configuration examples in `testutil.OcspServiceMaker.getDesignatedOcspServiceConfiguration()`.
- `withOcspRequestTimeout(Duration ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.
- `withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.
- `withNonceDisabledOcspUrls(URI... urls)` – adds the given URLs to the list of OCSP responder access location URLs for which the nonce protocol extension will be disabled. Some OCSP responders don't support the nonce extension. Contains the ESTEID-2015 OCSP responder URL by default.

Extended configuration example:  

```php  
$validator = new AuthTokenValidatorBuilder()
->withSiteOrigin("https://example.org")
->withTrustedCertificateAuthorities(trustedCertificateAuthorities())
->withoutUserCertificateRevocationCheckWithOcsp()
->withDisallowedCertificatePolicies(["1.2.3"])
->withNonceDisabledOcspUrls(new Uri("http://aia.example.org/cert"))
->build();
```

### Certificates' *Authority Information Access* (AIA) extension

Unless a designated OCSP responder service is in use, it is required that the AIA extension that contains the certificate’s OCSP responder access location is present in the user certificate. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Possible validation errors  

The `validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `AuthTokenException`, the list of available exceptions is available [here](src/exceptions). Each exception file contains a documentation comment that describes under which conditions the exception is thrown.

## Stateful and stateless authentication

In the code examples above we use the Nextcloud ISession object to safely store challenge nonce into Nextcloud-managed session object. In case of cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the *HttpOnly*, *Secure* and *SameSite* attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896) and in the following [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.

# Challenge nonce generation

The authentication protocol requires support for generating challenge nonces, large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *random_bytes* PHP built-in function as the secure random source and the `ChallengeNonceStore` interface for storing issued challenge nonces.

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Make sure that challenge nonces are correctly issued](#6-make-sure-that-challenge-nonces-are-correctly-issued)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage

As described in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*, the only mandatory configuration parameter of the challenge nonce generator is the challenge nonce store.

The challenge nonce store is used to save the nonce value along with the nonce expiry time. It must be possible to look up the challenge nonce data structure from the store using an identifier specific to the browser session. The values from the store are used by the token validator as described in the section *[Authentication token validation > Basic usage](#basic-usage)* that also contains recommendations for store usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```php
$challengeNonce = $generator->generateAndStoreNonce();
```

The `generateAndStoreNonce()` method both generates the nonce and saves it in the store.

## Extended configuration  

The following additional configuration options are available in `NonceGeneratorBuilder`:

- `withNonceTtl(Duration duration)` – overrides the default challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default challenge nonce time-to-live is 5 minutes.
- `withSecureRandom(SecureRandom)` - allows to specify a custom `SecureRandom` instance.

Extended configuration example:  

```php  
$generator = new ChallengeNonceGeneratorBuilder()  
->withChallengeNonceStore($store)
->withNonceTtl(300) // 5 minutes
->withSecureRandom($customSecureRandom)  
->build();
```

# Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

# Testing

You can run phpunit in root directory to launch all unit tests.

``` bash
phpunit
```

# Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

# Security

If you discover any security related issues, please email pmuzikant@email.cz instead of using the issue tracker.

# Credits

- [Petr Muzikant][link-author]
- [Web-eID contributors](https://github.com/orgs/web-eid/people)
- [All Contributors][link-contributors]

# License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.


[ico-version]: <https://img.shields.io/packagist/v/Muzosh/web_eid_authtoken_validation_php.svg?style=flat-square>
[ico-license]: <https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square>
[ico-travis]: <https://img.shields.io/travis/Muzosh/web_eid_authtoken_validation_php/master.svg?style=flat-square>
[ico-scrutinizer]: <https://img.shields.io/scrutinizer/coverage/g/Muzosh/web_eid_authtoken_validation_php.svg?style=flat-square>
[ico-code-quality]: <https://img.shields.io/scrutinizer/g/Muzosh/web_eid_authtoken_validation_php.svg?style=flat-square>
[ico-downloads]: <https://img.shields.io/packagist/dt/Muzosh/web_eid_authtoken_validation_php.svg?style=flat-square>

[link-packagist]: https://packagist.org/packages/Muzosh/web_eid_authtoken_validation_php
[link-downloads]: https://packagist.org/packages/Muzosh/web_eid_authtoken_validation_php
[link-author]: https://github.com/Muzosh
[link-contributors]: ../../contributors
