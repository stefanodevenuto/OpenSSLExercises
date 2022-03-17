/* Using OpenSSL, generate two 256 bit integers, 
   sum them (modulo 2^256) and print the result. */

#include <stdio.h>
#include <math.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#define RAND_SIZE 32
#define SEED_SIZE 64

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

void print_bytes(unsigned char random_bytes[]) {
  for (int i = 0; i < RAND_SIZE; i++)
    printf("%02X ", random_bytes[i]);
  printf("\n");
}


int main() {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* result = BN_new();
  BIGNUM* tmp1 = BN_new();
  BIGNUM* tmp2 = BN_new();
  BIGNUM* a = BN_new();
  BIGNUM* b = BN_new();
  BIGNUM* m = BN_new();

  // Load OpenSSL facilities
  ERR_load_crypto_strings();

  BN_set_word(tmp1, 2);
  BN_set_word(tmp2, 256);

  // Generate first number
  if(!BN_rand(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    handle_errors();

  printf("A: ");
  BN_print_fp(stdout, a);
  printf("\n");

  // Generate second number
  if(!BN_rand(b, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    handle_errors();

  printf("B: ");
  BN_print_fp(stdout, b);
  printf("\n");

  // Generate modulus
  if(!BN_exp(m, tmp1, tmp2, ctx))
    handle_errors();

  BN_free(tmp1);
  BN_free(tmp2);

  // Result
  if(!BN_mod_add(result, a, b, m, ctx))
    handle_errors();

  printf("Result: ");
  BN_print_fp(stdout, result);
  printf("\n");

  // Free all
  BN_free(a);
  BN_free(b);
  BN_free(m);
  BN_free(result);

  BN_CTX_free(ctx);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}