/* Using OpenSSL, generate two 256 bit integers, 
   sum them (modulo 2^256) and print the result. */

#include <stdio.h>
#include <math.h>
#include <stdlib.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#define RAND_SIZE 32
#define SEED_SIZE 64

#define TO_INT256(bytes) (bytes[0]  << 120 | bytes[1]  << 112 | bytes[2]  << 104 | bytes[3]  << 96 \
                          bytes[4]  <<  88 | bytes[5]  <<  80 | bytes[6]  <<  72 | bytes[7]  << 64 \
                          bytes[8]  <<  56 | bytes[9]  <<  48 | bytes[10] <<  40 | bytes[11] << 32 \
                          bytes[12] <<  24 | bytes[13] <<  16 | bytes[14] <<   8 | bytes[15])

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

  int random_number1[2];
  int random_number2[2];

  if(RAND_load_file("/dev/random", SEED_SIZE) != SEED_SIZE)
    dump_error_and_abort();

  if(RAND_bytes(random_bytes1, RAND_SIZE) != 1)
    dump_error_and_abort();

  random_number1 = TO_INT256(random_bytes1);
  printf("First number: %d\n", random_number1);

  if(RAND_bytes(random_bytes2, RAND_SIZE) != 1)
    dump_error_and_abort();

  random_number2 = TO_INT256(random_bytes2);
  printf("Second number: %d\n", random_number2);







  printf("Result: %d", (random_number1 * random_number2) % (int)pow(2, 32));


  return 0;
}