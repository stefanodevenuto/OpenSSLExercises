# Exercises

1. Write a program in C that, using the OpenSSL library, computes the hash of the content of a file using SHA256 (or or SHA 512 or SHA3).
The filename is passed as first parameter from the command line.

2. Write a program in C that, using the OpenSSL library, computes the hash of the concatenation of two files using SHA256 (or or SHA 512 or SHA3).
The filenames are passed as first and second parameters from the command line.

3. Writes a program in C that, using the OpenSSL library, computes the hash of the content of a file, passed as first parameter from the command line, using the algorithm passed as second parameter.
HINT: check the EVP_get_digestbyname function (or the EVP_MD_fetch if you are using OpenSSL 3.0+ https://www.openssl.org/docs/man3.0/man7/crypto.html).

4. Using OpenSSL, compute the digest of the file passed as first parameter from the command line with both SHA256 and SHA512.
Then, name sha512_low and sha512_high the first 256 bits and the last 256 of the SHA512 digest, respectively, and sha256 the digest computed with SHA356, you have to compute print on the standard output the following operation:

sha256 XOR (sha512_low AND SHA512_high)

