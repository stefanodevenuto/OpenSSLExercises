# Exercises

1. Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.
The filename is passed as first parameter from the command line, the algorithm is passed as second parameter and must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb).

2. Write a program that decrypts the content of a file, passed as the first parameter from the command line, using the key and IV passed as the second and third parameters. The program must save the decrypted file into a file whose name is the fourth parameter (i.e., decrypt the result of the encrpytion of enc4.c on GitHub).

3. Implement a program that encrypts a file, passed as the first parameter from the command line, using a stream cipher. Using the C XOR function, apply a mask 128bit mask (of your choice, or just select '11..1'), decrypt and check the result.

4. Find a way in the OpenSSL documentation to encrypt, using a block cipher, a message passed as first parameter from the command line, without padding the last block (and manage the possible errors).
