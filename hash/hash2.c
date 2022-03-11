#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

void print_usage(char* filename) {
  printf("Usage: %s filename filename", filename);
}

void print_bytes(unsigned char bytes[], int n) {
  for (int i = 0; i < n; i++)
    printf("%02x", bytes[i]);
  printf("\n");
}

void open_update_close(EVP_MD_CTX* md, char* filename) {
  unsigned char buffer[MAXBUF];
  int n_read;
  FILE* f;

  // Open the file
  if((f = fopen(filename,"r")) == NULL) {
    fprintf(stderr,"Error on opening the file\n");
    exit(1);
  }

  // Read and incrementally compute the digest
  while((n_read = fread(buffer, 1, MAXBUF, f)) > 0){
    if(!EVP_DigestUpdate(md, buffer, n_read))
      handle_errors();
  }

  fclose(f);
}

int main(int argc, char** argv) {
  unsigned char md_value[EVP_MD_size(EVP_sha256())];
  EVP_MD_CTX* md;
  int md_len;

  if (argc < 3) {
    fprintf(stderr, "Missing parameter\n");
    print_usage(argv[0]);
    return 1;
  }

  // Load OpenSSL facilities
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  // Create and Initialize Context
  md = EVP_MD_CTX_new();
  if(!EVP_DigestInit(md, EVP_sha256()))
    handle_errors();

  open_update_close(md, argv[1]);
  open_update_close(md, argv[2]);

  // Finalize
  if(!EVP_DigestFinal_ex(md, md_value, &md_len))
    handle_errors();

  printf("Digest of %s: ", argv[1]);
  print_bytes(md_value, md_len);

  // Free all
  EVP_MD_CTX_free(md);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
