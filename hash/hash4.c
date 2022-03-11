#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

void print_usage(char* filename) {
  printf("Usage: %s filename", filename);
}

void print_bytes(unsigned char bytes[], int n) {
  for (int i = 0; i < n; i++)
    printf("%02x", bytes[i]);
  printf("\n");
}

int main(int argc, char** argv) {
  unsigned char md_value_sha256[EVP_MD_size(EVP_sha256())];
  unsigned char md_value_sha512[EVP_MD_size(EVP_sha512())];

  unsigned char and_bitted[EVP_MD_size(EVP_sha512()) / 2];
  unsigned char xored[EVP_MD_size(EVP_sha512()) / 2];

  unsigned char buffer[MAXBUF];
  EVP_MD_CTX* md_sha256;
  EVP_MD_CTX* md_sha512;
  FILE* f;
  int n_read;
  int md_len_sha256;
  int md_len_sha512;

  if (argc < 2) {
    fprintf(stderr, "Missing parameter\n");
    print_usage(argv[0]);
    return 1;
  }

  // Open the file
  if((f = fopen(argv[1],"r")) == NULL) {
    fprintf(stderr,"Error on opening the file\n");
    exit(1);
  }

  // Load OpenSSL facilities
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  // Create and Initialize SHA256 Context
  md_sha256 = EVP_MD_CTX_new();
  if(!EVP_DigestInit(md_sha256, EVP_sha256()))
    handle_errors();

  // Create and Initialize SHA512 Context
  md_sha512 = EVP_MD_CTX_new();
  if(!EVP_DigestInit(md_sha512, EVP_sha512()))
    handle_errors();

  // Read and incrementally compute the digest
  while((n_read = fread(buffer, 1, MAXBUF, f)) > 0){
    if(!EVP_DigestUpdate(md_sha256, buffer, n_read))
      handle_errors();

    if(!EVP_DigestUpdate(md_sha512, buffer, n_read))
      handle_errors();
  }

  // Finalize SHA256
  if(!EVP_DigestFinal_ex(md_sha256, md_value_sha256, &md_len_sha256))
    handle_errors();

  // Finalize SHA512
  if(!EVP_DigestFinal_ex(md_sha512, md_value_sha512, &md_len_sha512))
    handle_errors();

  printf("SHA256 (%s): ", argv[1]);
  print_bytes(md_value_sha256, md_len_sha256);

  printf("SHA512 (%s): ", argv[1]);
  print_bytes(md_value_sha512, md_len_sha512);

  for(int i = 0; i < md_len_sha256; i++)
    and_bitted[i] = md_value_sha512[i] & md_value_sha512[i+md_len_sha256];

  for(int i = 0; i < md_len_sha256; i++)
    xored[i] = md_value_sha256[i] ^ and_bitted[i];

  printf("RESULT (%s): ", argv[1]);
  print_bytes(xored, md_len_sha256);

  // Free all
  fclose(f);
  EVP_MD_CTX_free(md_sha256);
  EVP_MD_CTX_free(md_sha512);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
