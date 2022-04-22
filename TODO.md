
* add licences at the start of each file
* messages of Exception are not binary safe, maybe add some handling?
* make OCSP a standalone library
* phpseclib vs openssl PHP builtin functions
    * phpseclib
        * php5.6+
        * Extensions like bcmath, gmp, libsodium and openssl, if they're available, for speed, but they're not required.
    * openssl
        * more secure?
        * have some OpenSSLCertificate object, but no documentation and php 8.0.0+
    * phpseclib seems more robust, provides actuall ASN1 decoded objects and seems to be well established

NEXT:

* go through class variables and specify their type
* typehint everything
