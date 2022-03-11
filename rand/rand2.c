/* Writes a program in C that, using the OpenSSL library, generates randomly the private key to be used 
   for encrypting data with AES128 in CBC and the needed IV. Pay attention to select the proper PRNG. */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define SIZE 16

void dump_error_and_abort() {
  ERR_print_errors_fp(stderr);
}

void print_bytes(unsigned char random_bytes[]) {
  for (int i = 0; i < SIZE; i++)
    printf("%02X ", random_bytes[i]);
  printf("\n");
}

void print_usage(char* name) {
  printf("Usage: %s password", name);
}

int main(int argc, char** argv) {
  int n_rounds = 5;
  unsigned char key[16];
  unsigned char iv[16];

  if (argc < 2) {
    fprintf(stderr, "Missing parameter\n");
    print_usage(argv[0]);
    return 1;
  }

  unsigned char* key_data = (unsigned char *) argv[1];
  
  if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), NULL, key_data, strlen(key_data), n_rounds, key, iv) != 16) {
    dump_error_and_abort();
    return 1;
  }

  printf("Key is:\t");
  print_bytes(key);

  printf("IV is:\t");
  print_bytes(iv);

  return 0;
}