Overview & Requirements
=======================

This repository contains a number of small standalone utilities that perform
tasks related to certificate transparency on X.509 certificates.

These utilities depend on OpenSSL as well as BinPAC (see https://github.com/bro/binpac
and https://www.bro.org/sphinx/components/binpac/README.html).

getTbsCertificate
=================

Extracts the tbscertificate from a file containing certificates, while removing
either the poison or sct extension from the certificate. Source file is named
"certificates" end expects base64-encoded certificates. Choice of poison or sct removal
is made via a command-line argument (start without argument for usage).


validateSct
===========

Check a given SCT against a list of certificates. Outputs if a certificate matches.

Certificates are expected in file certificates_scttest, base64-encoded, one per line.

Command-line parameters:

validateSct [log key] [timestamp] [signature]
log key and signature expected in base64.

Example run:

```
$ ./validateSct MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA== 1406997753366 MEQCIBxLgl2Vbmdb2wSVS/bO9DI+hnp6MqsYYHTeCNoFkUwvAiBzVBtuf6GwfRG85vOFL5dmGveK5BAljxL0bzkP0p4Y8A==
Log key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==
Timestamp: 1406997753366
Signature: MEQCIBxLgl2Vbmdb2wSVS/bO9DI+hnp6MqsYYHTeCNoFkUwvAiBzVBtuf6GwfRG85vOFL5dmGveK5BAljxL0bzkP0p4Y8A==
Valid SCT test	2	53fd396c744d64677d3bc4eb06eafdd78f442	4c3fbfbac7589ee68d753f806acc822cbd5082c735fdc3fce3924dc32959288f
Done
```

In this case, the certificate in line 2 with the sha1
53fd396c744d64677d3bc4eb06eafdd78f442 and the sha256
4c3fbfbac7589ee68d753f806acc822cbd5082c735fdc3fce3924dc32959288f
matched the SCT.

All lines besides "Valid SCT test" are only status information and output to stderr.

extractSct
==========

ExtractSCT extracts the signed certificate timestamps from a list of certificates.
Certificates are expected in a file named "certificates", base64-encoded, one per file.

SCT information is sent to stdout with the following fields on each line (tab separated):

```
sha1 of certificate
sha256 of certificate
SCT version
SCT logid
SCT timestamp
SCT hash algorithm (numeric)
SCT signature algorithm (numeric)
SCT signature (base64 encoded)
```

errors are sent to stderr.

ValidateSelfsigned
==================

Check if a certificate is signed with the public key contained in the same certificate.
Expects input in a file named "certificates2", certificates have to be base64-encoded,
one per file.
