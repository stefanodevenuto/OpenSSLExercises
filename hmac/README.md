# Exercises

1. Write a program in C that, using the OpenSSL library, computes the HMAC of the content of a file using SHA256 (or or SHA 512 or SHA3).
The filename is passed as first parameter from the command line.

2. Write a program in C that, using the OpenSSL library, verifies that the HMAC of a file computed using SHA256 (or or SHA 512 or SHA3) equals the value that is passed as the first parameter from the command line.
The filename is passed as the second parameter from the command line.


3. Write a program in C that, using the OpenSSL library, computes the keyed digest of a files using SHA256 (or or SHA 512 or SHA3).
The filename is passed as the first parameter, the key is passed as the  second parameters from the command line.
The keyed digest is performed as HASH(k||file||k).

4. Write a program in C that manually implements the HMAC algorithm using OpenSSL (i.e., implements all the low-level transformation required to compute the HMAC, don't use the already provided interfaces like EVP_DigestSign_ or HMAC_). 