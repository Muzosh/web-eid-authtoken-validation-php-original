# web-eid-authtoken-validation-php
* PHP library used for validating [Web-eID token](https://github.com/web-eid)
  * follows same principles and functionality of existing [java](https://github.com/web-eid/web-eid-authtoken-validation-java) and [.net](https://github.com/web-eid/web-eid-authtoken-validation-dotnet) validation libraries
  * however in PHP there is no bouncy-castle, which is heavily used in existing libraries
  * most stuff (working with certificates, keys, cryptography, etc.) is replicated with [phpseclib](https://phpseclib.com/) library + OCSP request and response handling (creation, verification, etc.) is developed from scratch
* **Code-base with minimal viable product is basically done in the development branch**
* code-base details:
  * all unit-tests (with mocked certificates and tokens) ported from java library are functional
  * works with test EstEID from SK ID Solutions without problems
  * has all the functionality from other (Java and .NET) validation libraries
* what needs to be done to make version 1.0 in master:
  * finish most of the tasks in [TODO](https://github.com/Muzosh/web-eid-authtoken-validation-php/projects/1) github projects (documentation, PHPDocs, code-comments, etc.)
  * finish licencing (most probably will be MIT licence)
  * link with [twofactor_nextcloud](https://github.com/Muzosh/twofactor_webeid) repository as usage example
* ETA of version 1.0 - summer 2022
