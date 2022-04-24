<?php

declare(strict_types=1);

namespace muzosh\web_eid_authtoken_validation_php\certificate;

use DateInterval;
use DateTime;
use DateTimeZone;
use GuzzleHttp\Psr7\Uri;
use muzosh\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use muzosh\web_eid_authtoken_validation_php\testutil\AuthTokenValidators;
use muzosh\web_eid_authtoken_validation_php\util\TitleCase;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

include './src/util/Logger.php';
include './src/util/TrustedCertificates.php';

foreach (glob('src/util/OCSP/Maps/*.php') as $filename) {
    include $filename;
}

include './src/util/TypedArrayUtil.php';

require __DIR__.'/vendor/autoload.php';

// $placeholder = new PublicKey();

$certificate = 'MIIEAzCCA2WgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9fAmiPGWT++GuOVoZQY3XxijggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOQsvTQJEBVMMSmhyZX5bibYJubAMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgH1UsmMdtLZti51Fq2QR4wUkAwpsnhsBV2HQqUXFYBJ7EXnLCkaXjdZKkHpABfM0QEx7UUhaI4i53jiJ7E1Y7WOAAJBDX4z61pniHJapI1bkMIiJQ/ti7ha8fdJSMSpAds5CyHIyHkQzWlVy86f9mA7Eu3oRO/1q+eFUzDbNN3Vvy7gQWQ=';

$certificate2 = 'MIIFwjCCA6qgAwIBAgIQY+LgQ6n0BURZ048wIEiYHjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNURUlELVNLIDIwMTUwHhcNMTcxMDAzMTMyMjU2WhcNMjIxMDAyMjA1OTU5WjCBnjELMAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEaMBgGA1UECwwRZGlnaXRhbCBzaWduYXR1cmUxJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDYxNzEwMDMwMTYzMRAwDgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzYxNzEwMDMwMTYzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+nNdtmZ2Ve3XXtjBEGwpvVrDIg7slPfLlyHbCBFMXevfqW5KsXIOy6E2A+Yof+/cqRlY4IhsX2Ka9SsJSo8/EekasFasLFPw9ZBE3MG0nn5zaatg45VSjnPinMmrzFzxo4IB2jCCAdYwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwgYsGA1UdIASBgzCBgDBzBgkrBgEEAc4fAwEwZjAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1bS9DUFMwMwYIKwYBBQUHAgIwJwwlQWludWx0IHRlc3RpbWlzZWtzLiBPbmx5IGZvciB0ZXN0aW5nLjAJBgcEAIvsQAECMB0GA1UdDgQWBBTiw6M0uow+u6sfhgJAWCSvtkB/ejAiBggrBgEFBQcBAwQWMBQwCAYGBACORgEBMAgGBgQAjkYBBDAfBgNVHSMEGDAWgBRJwPJEOWXVm0Y7DThgg7HWLSiGpjCBgwYIKwYBBQUHAQEEdzB1MCwGCCsGAQUFBzABhiBodHRwOi8vYWlhLmRlbW8uc2suZWUvZXN0ZWlkMjAxNTBFBggrBgEFBQcwAoY5aHR0cHM6Ly9zay5lZS91cGxvYWQvZmlsZXMvVEVTVF9vZl9FU1RFSUQtU0tfMjAxNS5kZXIuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly93d3cuc2suZWUvY3Jscy9lc3RlaWQvdGVzdF9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAEWBdwmzo/yRncJXKvrE+A1G6yQaBNarKectI5uk18BewYEA4QkhmIwOCwD83jBDB9JF+kuODMHsnvz2mfhwaB/uJIPwfBDQ5JCMBdHPsxLN9nzW/UUzqv2UDMwFkibHCcfV5lTBcmOd7FagUHTUm+8gRlWbDiVl5yPochdJgGYPV+fs/jc5ttHaBvBon0z9LbI4qi0VXdRmV0iogErh8JF5yfGkbfGRaMkWkNYQtQ68i/hPe6MaUxL2/MMt4YTyXtVghmc3ZKZIyp4j0+jlK4vL+d4gaE+TvoQvh6HrmP145FqlMDurATWdB069+hdDLO5fI6AYkc79D5XPKwQ/f1MBufLtBYtOJmtpLT+tdBt/EqOEIO/0FeHcXZlFioNMuxBBeTE/QcDtJ2jxTcg8jNOoepS0wjuxBon9iI1710SR53DLGSWdL52lPoBFacnyPQI1htXVUkJ8icMQKYe3BLt1Ha2cvsA4n4IpjqVROX4mzoPL1hg/aJlD+W2uI2ppYRUNY5FX7C0R+AYzMpOahQ7STQfUxtEnKW98e1I33LWwpjJW9q4htsZeXs4Zatf9ssfUW0VA49tnI28kkN2D8aw1NgWfzVlnJKkEj0qa3ewLZK577j8MexAetT/7leH6mqewr9ewC/tKbYjhufieXx6RPcRC4OZsxtii7ih8TqRg=';

$tokenOrigin = 'https://ria.ee';
$tokenNonce = '12345678123456781234567812345678912356789123';
$tokenRsa = json_decode('{"algorithm":"RS256",'.
    '"unverifiedCertificate":"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",'.
    '"issuerApp":"https://web-eid.eu/web-eid-app/releases/2.0.0+0",'.
    '"signature":"xsjXsQvVYXWcdV0YPhxLthJxtf0//R8p9WFFlYJGRARrl1ruyoAUwl0xeHgeZOKeJtwiCYCNWJzCG3VM3ydgt92bKhhk1u0JXIPVqvOkmDY72OCN4q73Y8iGSPVTgjk93TgquHlodf7YcqZNhutwNNf3oldHEWJD5zmkdwdpBFXgeOwTAdFwGljDQZbHr3h1Dr+apUDuloS0WuIzUuu8YXN2b8lh8FCTlF0G0DEjhHd/MGx8dbe3UTLHmD7K9DXv4zLJs6EF9i2v/C10SIBQDkPBSVPqMxCDPECjbEPi2+ds94eU7ThOhOQlFFtJ4KjQNTUa2crSixH7cYZF2rNNmA==",'.
    '"format":"web-eid:1.0"}');

$tokenEc = json_decode('{"algorithm":"ES384",'.
    '"unverifiedCertificate":"MIIEAzCCA2WgAwIBAgIQHWbVWxCkcYxbzz9nBzGrDzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAyMzE1MzM1OVoXDTIzMTAyMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ/u+9IncarVpgrACN6aRgUiT9lWC9H7llnxoEXe8xoCI982Md8YuJsVfRdeG5jwVfXe0N6KkHLFRARspst8qnACULkqFNat/Kj+XRwJ2UANeJ3Gl5XBr+tnLNuDf/UiR6jggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOTddHnA9rJtbLwhBNyn0xZTQGCMMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgHYElkX4vn821JR41akI/lpexCnJFUf4GiOMbTfzAxpZma333R8LNrmI4zbzDp03hvMTzH49g1jcbGnaCcbboS8DAJBObenUp++L5VqldHwKAps61nM4V+TiLqD0jILnTzl+pV+LexNL3uGzUfvvDNLHnF9t6ygi8+Bsjsu3iHHyM1haKM=",'.
    '"appVersion":"https://web-eid.eu/web-eid-app/releases/2.0.0+0",'.
    '"signature":"tbMTrZD4CKUj6atjNCHZruIeyPFAEJk2htziQ1t08BSTyA5wKKqmNmzsJ7562hWQ6+tJd6nlidHGE5jVVJRKmPtNv3f9gbT2b7RXcD4t5Pjn8eUCBCA4IX99Af32Z5ln",'.
    '"format":"web-eid:1"}');

const AUTH_TOKEN = '{"algorithm":"ES384",' .
	'"unverifiedCertificate":"MIIEAzCCA2WgAwIBAgIQHWbVWxCkcYxbzz9nBzGrDzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAyMzE1MzM1OVoXDTIzMTAyMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ/u+9IncarVpgrACN6aRgUiT9lWC9H7llnxoEXe8xoCI982Md8YuJsVfRdeG5jwVfXe0N6KkHLFRARspst8qnACULkqFNat/Kj+XRwJ2UANeJ3Gl5XBr+tnLNuDf/UiR6jggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOTddHnA9rJtbLwhBNyn0xZTQGCMMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgHYElkX4vn821JR41akI/lpexCnJFUf4GiOMbTfzAxpZma333R8LNrmI4zbzDp03hvMTzH49g1jcbGnaCcbboS8DAJBObenUp++L5VqldHwKAps61nM4V+TiLqD0jILnTzl+pV+LexNL3uGzUfvvDNLHnF9t6ygi8+Bsjsu3iHHyM1haKM=",' .
	'"appVersion":"https://web-eid.eu/web-eid-app/releases/2.0.0+0",' .
	'"signature":"tbMTrZD4CKUj6atjNCHZruIeyPFAEJk2htziQ1t08BSTyA5wKKqmNmzsJ7562hWQ6+tJd6nlidHGE5jVVJRKmPtNv3f9gbT2b7RXcD4t5Pjn8eUCBCA4IX99Af32Z5ln",' .
	'"format":"web-eid:1"}';
const VALID_CHALLENGE_NONCE = '12345678123456781234567812345678912356789123';

$uri =new Uri('https:///ria.ee');

$token = $tokenEc;

$cert = new X509();
$cert->loadX509($certificate);
// $cert->saveX509($cert->getCurrentCert(), X509::FORMAT_DER);
$cert->loadCA(file_get_contents('./certs/TEST_of_ESTEID2018.cer'));

$token = new WebEidAuthToken(json_encode($tokenEc));
// $x509->saveX509($x509->getCurrentCert(), X509::FORMAT_DER);
// $x501 = new X509();
// $x501->loadX509(file_get_contents('./certs/ESTEID2018.cer'));
// $x502 = new X509();
// $x502->loadX509(file_get_contents('./certs/TEST_of_ESTEID2018.cer'));

// key data: [4, 1, -59, -117, -96, -31, -63, 42, -62, 98, 35, -5, 116, -43, 105, 73, 97, 127, 16, -107, -12, 84, 32, 126, -24, 37, 11, 111, -12, 83, 29, 72, 122, -84, 53, -42, 96, -29, 54, -7, -58, 38, 25, 22, -59, -94, -37, 88, -104, -69, 66, -37, 97, 48, 110, 81, -41, 78, 37, -20, -38, 123, -108, 23, -81, -84, 24, 1, 14, -41, -32, -115, -81, 94, -36, -62, -45, 66, 70, 62, 112, 84, -66, 81, 12, 99, -73, -42, 98, -123, 53, 9, 86, -60, 123, -106, -116, 24, -107, -95, -124, -118, -86, -84, 25, -79, 33, -105, 7, -18, -37, -75, -20, -101, -58, -10, -82, 20, -94, 76, -21, -51, 118, 52, -19, 27, -98, -51, -97, 5, 64, 95, -24]
// hash: [-64, -124, -103, 41, -60, 78, -97, 59, 2, 52, -10, -103, -31, 10, 86, 0, 8, 41, 62, 123]

$string = 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBxYug4cEqwmIj+3TVaUlhfxCV9FQgfuglC2/0Ux1Ieqw11mDjNvnGJhkWxaLbWJi7QtthMG5R104l7Np7lBevrBgBDtfgja9e3MLTQkY+cFS+UQxjt9ZihTUJVsR7lowYlaGEiqqsGbEhlwfu27Xsm8b2rhSiTOvNdjTtG57NnwVAX+g=';

$publicKey = $cert->getChain()[1]->getCurrentCert()['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];

$extracted = ASN1::extractBER($publicKey);
$decoded = ASN1::decodeBER($extracted);

$unpacked = array_slice(unpack('c*', $decoded[0]['content'][1]['content']), 1);
$packed = pack('c*', ...$unpacked);

$publicKeyHash = hash('sha1', $packed, true);
$unpacked = unpack('c*', $publicKeyHash);

$request = array(48, 106, 48, 104, 48, 75, 48, 73, 48, 71, 48, 7, 6, 5, 43, 14, 3, 2, 26, 4, 20, 50, -105, 66, -110, -100, 102, -11, 87, 11, -49, -45, 36, -114, 84, -120, -42, -47, -82, -85, -85, 4, 20, -64, -124, -103, 41, -60, 78, -97, 59, 2, 52, -10, -103, -31, 10, 86, 0, 8, 41, 62, 123, 2, 16, 57, 105, 1, 89, 115, 67, 38, 109, 91, -56, 87, 119, 94, -59, -92, -66, -94, 25, 48, 23, 48, 21, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 8, -46, 123, 90, -47, -94, 43, -38, 53);

$response = array(48, -126, 6, 39, 10, 1, 0, -96, -126, 6, 32, 48, -126, 6, 28, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 1, 4, -126, 6, 13, 48, -126, 6, 9, 48, -126, 1, 40, -95, 116, 48, 114, 49, 55, 48, 53, 6, 3, 85, 4, 3, 12, 46, 68, 69, 77, 79, 32, 111, 102, 32, 69, 83, 84, 69, 73, 68, 45, 83, 75, 32, 50, 48, 49, 56, 32, 65, 73, 65, 32, 79, 67, 83, 80, 32, 82, 69, 83, 80, 79, 78, 68, 69, 82, 32, 50, 48, 49, 56, 49, 13, 48, 11, 6, 3, 85, 4, 11, 12, 4, 79, 67, 83, 80, 49, 27, 48, 25, 6, 3, 85, 4, 10, 12, 18, 83, 75, 32, 73, 68, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 32, 65, 83, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 69, 69, 24, 15, 50, 48, 50, 50, 48, 52, 50, 50, 49, 54, 53, 49, 49, 57, 90, 48, -127, -125, 48, -127, -128, 48, 71, 48, 7, 6, 5, 43, 14, 3, 2, 26, 4, 20, 50, -105, 66, -110, -100, 102, -11, 87, 11, -49, -45, 36, -114, 84, -120, -42, -47, -82, -85, -85, 4, 20, -64, -124, -103, 41, -60, 78, -97, 59, 2, 52, -10, -103, -31, 10, 86, 0, 8, 41, 62, 123, 2, 16, 57, 105, 1, 89, 115, 67, 38, 109, 91, -56, 87, 119, 94, -59, -92, -66, -128, 0, 24, 15, 50, 48, 50, 50, 48, 52, 50, 50, 49, 54, 53, 49, 49, 57, 90, -95, 34, 48, 32, 48, 30, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 6, 4, 17, 24, 15, 50, 48, 49, 56, 48, 52, 48, 53, 48, 57, 52, 53, 50, 49, 90, -95, 25, 48, 23, 48, 21, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 8, -46, 123, 90, -47, -94, 43, -38, 53, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 3, -126, 1, 1, 0, -78, 48, 9, -66, 52, 37, -25, 23, 76, -96, -116, -20, -111, 118, 16, 13, 67, 111, -84, 1, -120, -28, 47, -94, -11, -9, 31, 66, -112, -104, 27, -37, 78, 96, -34, -114, 39, 69, 103, -126, 46, -84, -125, 60, -74, -3, 40, 62, 80, 24, -88, 43, -119, 57, -71, 7, 49, 79, -48, -113, 9, -62, -44, -42, -73, 56, -7, 92, 72, 117, 100, -63, 71, 116, -113, 5, 98, 18, -61, 107, -36, -89, 25, -49, -125, -109, 79, -84, -29, 76, 20, 26, 121, -78, -108, -58, -94, -78, 69, -24, -65, -119, -7, -1, 49, -82, -89, -89, -118, -117, -27, 85, -39, 17, 111, -71, 93, -26, -95, 67, 62, 41, 13, -106, 66, 24, -115, -97, -97, -69, 120, -6, -13, -93, 12, 111, 20, 118, -90, 113, 3, 71, -44, 125, -70, -66, 107, -25, 19, -9, -9, -15, 105, 85, 119, -41, 12, -113, -46, -5, 42, 31, -44, -118, -76, 4, -1, 37, -63, 76, -71, 7, -56, 49, -18, 29, 48, 74, 47, -8, 73, 113, 109, -120, 71, 75, 92, -14, 52, -93, 31, 2, -111, 28, 6, -60, 103, 48, -72, -17, -96, -82, 29, -22, -43, 16, -106, 126, -94, 40, -60, 19, -121, -72, 65, 12, -120, 25, 32, 88, 65, -111, -80, 110, -4, -56, 78, -44, 109, 117, -89, -30, -3, 101, 100, -99, 42, 28, 47, 39, 29, 106, -99, 107, 124, -45, -78, -42, -38, 29, 60, 76, 78, 113, 56, 47, -96, -126, 3, -59, 48, -126, 3, -63, 48, -126, 3, -67, 48, -126, 3, 31, -96, 3, 2, 1, 2, 2, 16, 122, -19, -123, 24, -104, -101, -32, -100, 91, -31, -69, -100, 16, 25, 50, 112, 48, 10, 6, 8, 42, -122, 72, -50, 61, 4, 3, 4, 48, 96, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 69, 69, 49, 27, 48, 25, 6, 3, 85, 4, 10, 12, 18, 83, 75, 32, 73, 68, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 32, 65, 83, 49, 23, 48, 21, 6, 3, 85, 4, 97, 12, 14, 78, 84, 82, 69, 69, 45, 49, 48, 55, 52, 55, 48, 49, 51, 49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 84, 69, 83, 84, 32, 111, 102, 32, 69, 83, 84, 69, 73, 68, 50, 48, 49, 56, 48, 30, 23, 13, 49, 56, 49, 48, 51, 49, 50, 49, 48, 48, 48, 48, 90, 23, 13, 51, 51, 48, 56, 50, 57, 50, 49, 48, 48, 48, 48, 90, 48, 114, 49, 55, 48, 53, 6, 3, 85, 4, 3, 12, 46, 68, 69, 77, 79, 32, 111, 102, 32, 69, 83, 84, 69, 73, 68, 45, 83, 75, 32, 50, 48, 49, 56, 32, 65, 73, 65, 32, 79, 67, 83, 80, 32, 82, 69, 83, 80, 79, 78, 68, 69, 82, 32, 50, 48, 49, 56, 49, 13, 48, 11, 6, 3, 85, 4, 11, 12, 4, 79, 67, 83, 80, 49, 27, 48, 25, 6, 3, 85, 4, 10, 12, 18, 83, 75, 32, 73, 68, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 32, 65, 83, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 69, 69, 48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -71, 21, -126, 37, -46, -110, 122, 52, -55, -17, -53, -58, 79, -39, -63, -47, -10, 26, -122, 34, 121, -23, 94, -51, -118, 27, -13, -92, 110, 1, 55, -35, -115, 86, -95, 63, -21, 11, 105, 98, -84, -73, 81, -89, -91, 50, 25, 97, -31, 69, 113, -13, -88, 20, -114, 103, 16, -125, 6, 49, 39, 89, 117, -101, -123, 96, 43, -89, -14, -17, 0, 118, 25, -49, 54, 46, 115, -38, -32, 120, -30, -108, -18, 20, 82, -62, -114, -40, -118, -71, -91, -59, -83, -13, 46, -12, 20, -95, 39, 27, 56, 55, -38, 14, -71, -81, -42, 7, 83, -41, 9, 117, 36, -8, 87, -116, -122, -27, -44, 68, 56, -100, 107, -32, 31, 108, 99, 82, 48, -41, -37, -83, -22, -29, -24, -113, 76, -2, 24, -75, 7, -117, -126, 88, -66, 114, 76, 97, 51, -50, -58, -8, 119, -78, -99, -67, 110, 86, -12, 23, 7, 60, -39, -63, -78, -17, -26, 55, -117, 67, -19, 101, 50, -124, -49, -52, -75, -113, -84, -107, -111, -53, -109, -69, 33, 84, 104, 118, -67, 1, -106, 52, -4, -44, -36, -1, -96, -103, 109, 37, 63, -44, -24, 106, -84, 85, 58, 47, -77, -96, -112, 107, 101, 52, 98, 78, -4, 70, -115, 109, -121, 119, -37, 123, 117, -48, -37, -121, 19, 4, 67, 8, -75, 51, 25, 110, 70, -1, 7, -79, -62, 103, 13, -67, -68, -109, -20, 97, 88, -127, -15, 121, -12, -45, -13, -69, 2, 3, 1, 0, 1, -93, -127, -35, 48, -127, -38, 48, 14, 6, 3, 85, 29, 15, 1, 1, -1, 4, 4, 3, 2, 7, -128, 48, 22, 6, 3, 85, 29, 37, 1, 1, -1, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 9, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 87, -57, 32, -3, -50, -5, -101, -19, 68, 8, -8, -120, 110, 123, 22, -78, -57, -33, -119, -12, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, -128, 20, -64, -124, -103, 41, -60, 78, -97, 59, 2, 52, -10, -103, -31, 10, 86, 0, 8, 41, 62, 123, 48, 81, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 69, 48, 67, 48, 65, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, -122, 53, 104, 116, 116, 112, 115, 58, 47, 47, 115, 107, 46, 101, 101, 47, 117, 112, 108, 111, 97, 100, 47, 102, 105, 108, 101, 115, 47, 84, 69, 83, 84, 95, 111, 102, 95, 69, 83, 84, 69, 73, 68, 50, 48, 49, 56, 46, 100, 101, 114, 46, 99, 114, 116, 48, 12, 6, 3, 85, 29, 19, 1, 1, -1, 4, 2, 48, 0, 48, 15, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 5, 4, 2, 5, 0, 48, 10, 6, 8, 42, -122, 72, -50, 61, 4, 3, 4, 3, -127, -117, 0, 48, -127, -121, 2, 66, 1, -124, -6, -108, -46, -107, -89, -64, -123, 87, 51, -54, 105, -9, -14, 74, -41, 90, 55, 2, 70, 65, 85, -28, 59, 93, -91, 30, -117, -98, -33, 74, -9, 110, -96, -77, -86, 124, -92, 4, 121, 75, 99, 32, 127, 69, -45, 19, -91, -106, -58, 120, -91, 9, -58, 11, 115, -124, 76, 10, -62, 2, 67, 123, -38, -125, 2, 65, 28, -122, 48, -34, 68, -96, -19, 14, -9, 82, 104, 0, 32, 36, -9, -23, 113, 24, 17, 68, 53, -1, 121, 106, -122, -68, 113, 39, -127, -116, 54, 69, -90, 3, -30, 107, -72, 29, -7, -62, 35, 60, 96, -49, 111, -119, -17, 124, -53, 59, 101, -120, 51, 70, 16, -33, -36, 17, -92, 29, -59, 74, -97, 32, 19);

// tbsResponseData = [48, -126, 1, 40, -95, 116, 48, 114, 49, 55, 48, 53, 6, 3, 85, 4, 3, 12, 46, 68, 69, 77, 79, 32, 111, 102, 32, 69, 83, 84, 69, 73, 68, 45, 83, 75, 32, 50, 48, 49, 56, 32, 65, 73, 65, 32, 79, 67, 83, 80, 32, 82, 69, 83, 80, 79, 78, 68, 69, 82, 32, 50, 48, 49, 56, 49, 13, 48, 11, 6, 3, 85, 4, 11, 12, 4, 79, 67, 83, 80, 49, 27, 48, 25, 6, 3, 85, 4, 10, 12, 18, 83, 75, 32, 73, 68, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 32, 65, 83, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 69, 69, 24, 15, 50, 48, 50, 50, 48, 52, 50, 50, 49, 54, 53, 49, 49, 57, 90, 48, -127, -125, 48, -127, -128, 48, 71, 48, 7, 6, 5, 43, 14, 3, 2, 26, 4, 20, 50, -105, 66, -110, -100, 102, -11, 87, 11, -49, -45, 36, -114, 84, -120, -42, -47, -82, -85, -85, 4, 20, -64, -124, -103, 41, -60, 78, -97, 59, 2, 52, -10, -103, -31, 10, 86, 0, 8, 41, 62, 123, 2, 16, 57, 105, 1, 89, 115, 67, 38, 109, 91, -56, 87, 119, 94, -59, -92, -66, -128, 0, 24, 15, 50, 48, 50, 50, 48, 52, 50, 50, 49, 54, 53, 49, 49, 57, 90, -95, 34, 48, 32, 48, 30, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 6, 4, 17, 24, 15, 50, 48, 49, 56, 48, 52, 48, 53, 48, 57, 52, 53, 50, 49, 90, -95, 25, 48, 23, 48, 21, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 8, -46, 123, 90, -47, -94, 43, -38, 53]

// signature = [-78, 48, 9, -66, 52, 37, -25, 23, 76, -96, -116, -20, -111, 118, 16, 13, 67, 111, -84, 1, -120, -28, 47, -94, -11, -9, 31, 66, -112, -104, 27, -37, 78, 96, -34, -114, 39, 69, 103, -126, 46, -84, -125, 60, -74, -3, 40, 62, 80, 24, -88, 43, -119, 57, -71, 7, 49, 79, -48, -113, 9, -62, -44, -42, -73, 56, -7, 92, 72, 117, 100, -63, 71, 116, -113, 5, 98, 18, -61, 107, -36, -89, 25, -49, -125, -109, 79, -84, -29, 76, 20, 26, 121, -78, -108, -58, -94, -78, 69, -24, -65, -119, -7, -1, 49, -82, -89, -89, -118, -117, -27, 85, -39, 17, 111, -71, 93, -26, -95, 67, 62, 41, 13, -106, 66, 24, -115, -97, -97, -69, 120, -6, -13, -93, 12, 111, 20, 118, -90, 113, 3, 71, -44, 125, -70, -66, 107, -25, 19, -9, -9, -15, 105, 85, 119, -41, 12, -113, -46, -5, 42, 31, -44, -118, -76, 4, -1, 37, -63, 76, -71, 7, -56, 49, -18, 29, 48, 74, 47, -8, 73, 113, 109, -120, 71, 75, 92, -14, 52, -93, 31, 2, -111, 28, 6, -60, 103, 48, -72, -17, -96, -82, 29, -22, -43, 16, -106, 126, -94, 40, -60, 19, -121, -72, 65, 12, -120, 25, 32, 88, 65, -111, -80, 110, -4, -56, 78, -44, 109, 117, -89, -30, -3, 101, 100, -99, 42, 28, 47, 39, 29, 106, -99, 107, 124, -45, -78, -42, -38, 29, 60, 76, 78, 113, 56, 47]

// ASN1::loadOIDs(array(
//     'id-pkix-ocsp-nonce' => '1.3.6.1.5.5.7.48.1.2',
//     'id-sha1' => '1.3.14.3.2.26',
//     'qcStatements(3)' => '1.3.6.1.5.5.7.1.3',
//     'street' => '2.5.4.9',
//     'id-pkix-ocsp-basic' => '1.3.6.1.5.5.7.48.1.1',
//     'id-pkix-ocsp' => '1.3.6.1.5.5.7.48.1',
//     'secp384r1' => '1.3.132.0.34',
// ));

// OCSP request
// $decodedRequest = ASN1::decodeBER(pack('c*', ...$request));

// $mappedRequest = ASN1::asn1map($decodedRequest[0], OcspOCSPRequest::MAP);

// // need to specify filters for TYPE_ANY values before encoding DER
// $encodedRequest = ASN1::encodeDER($mappedRequest, OcspOCSPRequest::MAP);

// // OCSP response
// $decodedResponse = ASN1::decodeBER(pack('c*', ...$response));

// $mappedResponse = ASN1::asn1map($decodedResponse[0], OcspOCSPResponse::MAP, array('response' => function ($encoded) {
//     return ASN1::asn1map(ASN1::decodeBER($encoded)[0], OcspBasicOcspResponse::MAP);
// }));

// $encodedResponse = ASN1::encodeDER($mappedResponse, OcspOCSPResponse::MAP, array('response' => function ($source) {
//     return ASN1::encodeDER($source, OcspBasicOcspResponse::MAP);
// }));

// $result = $x509->loadCA(file_get_contents('./certs/TEST_of_ESTEID-SK_2015.cer'));
// $result = $x509->loadCA(file_get_contents('./certs/TEST_of_ESTEID2018.cer'));
// $result = $x509->loadCA(file_get_contents('./certs/TEST_of_SK_OCSP_RESPONDER_2020.cer'));
// $x509->setStartDate(new DateTime('2000-01-01'));
// $x509->validateSignature();

// sha256WithRSAEncryption

// $ocspClient = OcspClientImpl::build(5);

// $certificateId = OcspUtil::getCertificateId($cert, $cert->getChain()[0]);

// $request = (new OcspRequestBuilder())->withCertificateId($certificateId)->enableOcspNonce(true)
//     ->build()
// ;
// $nonce = $request->getNonceExtension();

// $response = $ocspClient->request(new Uri('http://aia.demo.sk.ee/esteid2018'), $request->getEncodedDER());
// if ($response->getStatus() != OcspOCSPResponseStatus::MAP['mapping'][0]) {
//     throw new UserCertificateOCSPCheckFailedException('Response status: '.$response->getStatus());
// }

// $basicResponse = $response->getBasicResponse();

// $x555 = new X509();
// $x555->loadX509($basicResponse->getCerts()[0]);
// $publicKey = $x555->getPublicKey()->withHash('sha256');


// $encoded = $basicResponse->getEncodedResponseData();
// $signature = $basicResponse->getSignature();
// $a = $publicKey->verify($encoded, $signature);


// $producedAt = $basicResponse->getProducedAt();
// $velid = new AuthTokenValidationConfiguration();

// $uri = $cert->validateURL('http://aia.demo.sk.ee/esteid2018');

// // SIGNATURE TESTING
// $originHash = hash('sha384', $tokenOrigin, true);
// $nonceHash = hash('sha384', $tokenNonce, true);
// $concatSignedFields = $originHash.$nonceHash;
// $publicKey = $cert->getPublicKey()->withHash('sha384');

// // $publicKey = openssl_pkey_get_public(openssl_x509_read($certificate));
// $signatureDer = ASN1Util::transcodeSignatureToDER(Base64Util::decodeBase64ToArray($token->signature));
// // $foo = openssl_verify($concatSignedFields, $seclib['signature'], $publicKey, OPENSSL_ALGO_SHA384);

// $test = $publicKey->verify($concatSignedFields, pack('c*', ...$signatureDer));
// $test = $publicKey->verify($concatSignedFields, base64_decode($token->signature, true)); // works with RS256

// $x510 = clone $x509;
// $x510->setDNProp('CN', 'peterko');
// $array = array($x501, $x502, $x510);

// $ta = new TrustedAnchors($array);

// $logger = WebEidLogger::getLogger('test::class');

// $logger->debug("test message: ". (new DateInterval("PT2S"))->format("%H:%I:%S.%f"));

// URI TESTING


// $uri1 = new Uri("www.google.com");
// $uri2 = new Uri("www.seznam.com");
// $uri3 = new Uri("www.facenbook.com");
// $uri4 = new Uri("www.agrewaf.com");

// $a = new UriUniqueArray($uri1, $uri2, $uri3, $uri4);
// $uri = new Uri('httpfqewdfqs:/qwefq/ufqfri.qwefthephple1#$!%#!)aqwefgue.coqfqm:45/');
// $uri2 = new Uri('https://uri.thephpleague.com/');
// $uri3 = new Uri('https://uri.thephpleague.com:43/');

// $client = new Client([
// 	RequestOptions::ALLOW_REDIRECTS => false,
// 	RequestOptions::CONNECT_TIMEOUT => (float) 5,
// 	RequestOptions::TIMEOUT => (float) 5
// ]);
// $request = new Request("GET", $uri2, [
// 	'Content-Type' => 'test'
// ], 'test');

// $response = $client->send($request);
// $ua = new UriArray($uri, $uri2, $uri3);

// // 1. Verify that the URI can be converted to absolute URL.
// if (!UriInfo::isAbsolute($uri)) {
//     throw new InvalidArgumentException('Provided URI is not a valid URL');
// }
// $foo = Uri::createFromComponents(array(
//     'scheme' => 'https',
//     'host' => $uri->getHost(),
//     'port' => $uri->getPort(),
// ));

// $foo2 = Uri::createFromString(UriInfo::getOrigin($uri));

// // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
// if (!UriInfo::isSameDocument($uri, Uri::createFromString(UriInfo::getOrigin($uri)))) {
//     throw new InvalidArgumentException('Origin URI must only contain the HTTPS scheme, host and optional port component');
// }

// TOKEN TESTING
// $tok = '{
// 	"unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4...",
// 	"algorithm": "RS256",
// 	"appVersion": "https://web-eid.eu/web-eid-app/releases/v2.0.0"
//   }';

// $foo = new WebEidAuthToken($tok);

// $test = $x509->getExtension('id-ce-extKeyUsage');
// $test = $x509->getExtension('id-ce-certificatePolicies');

// $opensslr = \openssl_x509_read($certificate);
// $opensslp = \openssl_x509_parse($certificate);

// TITLE CASE TESTING
// title case
// ucwords(strtolower($openssl['subject']['GN']), '\-');

// DATE TIME TESTING
$dt = new DateTime("Thursday, August 26, 2021 5:46:40 PM");
$test = ASN1::decodeBER(pack('c*', ...[4, 64, 48, 62, 48, 50, 6, 11, 43, 6, 1, 4, 1, -125, -111, 33, 1, 2, 1, 48,
35, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 21, 104, 116, 116, 112, 115,
58, 47, 47, 119, 119, 119, 46, 115, 107, 46, 101, 101, 47, 67, 80, 83, 48,
8, 6, 6, 4, 0, -113, 122, 1, 2]));

$dt = new DateTime('now', new DateTimeZone('Europe/Prague'));

$seconds = 600.0;

$dt2 = new DateInterval('PT'.$seconds.'S');

$dt3 = (clone $dt)->sub(new DateInterval('PT'.$seconds.'S'));

$foo = 10;
