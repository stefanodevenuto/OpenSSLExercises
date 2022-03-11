/* Write a program in C that, using the OpenSSL library, generates two 128 bit random strings. */
/* Then, it XOR them (bitwise) and prints the result on the standard output as an hex string.  */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define RAND_SIZE 16
#define SEED_SIZE 64

void dump_error_and_abort() {
  ERR_print_errors_fp(stderr);
  abort();
}

void print_bytes(unsigned char random_bytes[]) {
  for (int i = 0; i < RAND_SIZE; i++)
    printf("%02X ", random_bytes[i]);
  printf("\n");
}

int main() {
  unsigned char random_bytes1[RAND_SIZE];
  unsigned char random_bytes2[RAND_SIZE];

  if(RAND_load_file("/dev/random", SEED_SIZE) != SEED_SIZE)
    dump_error_and_abort();

  if(RAND_bytes(random_bytes1, RAND_SIZE) != 1)
    dump_error_and_abort();

  printf("First string: ");
  print_bytes(random_bytes1);

  if(RAND_bytes(random_bytes2, RAND_SIZE) != 1)
    dump_error_and_abort();

  printf("Second string: ");
  print_bytes(random_bytes2);

  printf("XORed result: ");
  for (int i = 0; i < RAND_SIZE; i++)
    printf("%02X ", random_bytes1[i] ^ random_bytes2[i]);

	return 0;
}