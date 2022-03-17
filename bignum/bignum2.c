#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define RAND_SIZE 32
#define SEED_SIZE 64

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

void print_bytes(unsigned char bytes[], int n) {
  for (int i = 0; i < n; i++)
    printf("%02x", bytes[i]);
  printf("\n");
}

int main() {
  BIGNUM* g = BN_new();
  BIGNUM* p = BN_new();

  BIGNUM* x = BN_new();  
  BIGNUM* y = BN_new();

  BIGNUM* A = BN_new();
  BIGNUM* B = BN_new();

  BIGNUM* K_A = BN_new();
  BIGNUM* K_B = BN_new();

  BN_CTX* ctx = BN_CTX_new();
  
  // Load OpenSSL facilities
  ERR_load_crypto_strings();

  // Set Generator g to 2
  BN_set_word(g, 2);

  do {
    if(!BN_generate_prime_ex(p, 2048, 0, NULL, NULL, NULL))
      handle_errors();
  } while(BN_cmp(p, g) < -1);

  // Alice generate a random number
  BN_rand(x, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  printf("[+] Alice Random number: ");
  BN_print_fp(stdout, x);
  printf("\n");

  // Alice computes A = g^x mod p
  if(!BN_mod_exp(A, g, x, p, ctx))
    handle_errors();
  printf("[+] Alice Public Secret: ");
  BN_print_fp(stdout, A);
  printf("\n\n");

  // Bob generate a random number
  BN_rand(y, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  printf("[+] Bob Random number: ");
  BN_print_fp(stdout, y);
  printf("\n");

  // Bob computes B = g^y mod p
  if(!BN_mod_exp(B, g, y, p, ctx))
    handle_errors();
  printf("[+] Bob Public Secret: ");
  BN_print_fp(stdout, B);
  printf("\n\n");

  printf("[+] Alice sends A to Bob\n");
  printf("[+] Bob sends B to Alice\n\n");

  // Alice computes K_A = B^x mod p
  if(!BN_mod_exp(K_A, B, x, p, ctx))
    handle_errors();
  printf("[+] Alice Key: ");
  BN_print_fp(stdout, K_A);
  printf("\n");

  // Bob computes K_B = A^y mod p
  if(!BN_mod_exp(K_B, A, y, p, ctx))
    handle_errors();
  printf("[+] Bob Key: ");
  BN_print_fp(stdout, K_B);
  printf("\n\n");

  if(!BN_cmp(K_A, K_B))
    printf("[+] Keys exchanged correctly!\n");
  else
    printf("[-] ERROR: keys differ\n");

  // Free all
  BN_free(p);
  BN_free(g);
  BN_free(x);
  BN_free(y);
  BN_free(A);
  BN_free(B);
  BN_free(K_A);
  BN_free(K_B);

  BN_CTX_free(ctx);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();


  return 0;
}