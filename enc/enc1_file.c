#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024
#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

void print_usage(char* filename) {
  printf("Usage: %s filename algorithm password filename_out", filename);
}

void print_bytes(unsigned char bytes[], int n) {
  for (int i = 0; i < n; i++)
    printf("%02x", bytes[i]);
  printf("\n");
}

int main(int argc, char** argv) {
  unsigned char buffer[MAXBUF];
  int len, ciphertext_len = 0;
  const EVP_CIPHER* cipher_fun;
  EVP_CIPHER_CTX* ctx;
  int block_size;
  FILE* f_out;
  FILE* f_in;
  int n_read;

  if (argc < 5) {
    fprintf(stderr, "Missing parameter\n");
    print_usage(argv[0]);
    return 1;
  }

  // Recover the proper EVP_CIPHER if existent
  if ((cipher_fun = EVP_get_cipherbyname(argv[2])) == NULL) {
    fprintf(stderr, "Inexistent algorithm");
    return 1;
  }

  // Open the input file
  if((f_in = fopen(argv[1],"r")) == NULL) {
    fprintf(stderr,"Error on opening the input file\n");
    exit(1);
  }

  // Open the output file
  if((f_out = fopen(argv[4],"wb")) == NULL) {
    fprintf(stderr,"Error on opening the output file\n");
    exit(1);
  }

  block_size = EVP_CIPHER_block_size(cipher_fun);
  unsigned char key[block_size];
  unsigned char iv[block_size];
  unsigned char ciphertext[MAXBUF + block_size];

  // Generate key and IV based on password
  unsigned char* key_data = (unsigned char *) argv[3];
  if (EVP_BytesToKey(cipher_fun, EVP_sha1(), NULL, key_data, strlen(key_data), 5, key, iv) != block_size)
    handle_errors();

  printf("KEY:\t");
  print_bytes(key, block_size);
  printf("IV:\t");
  print_bytes(iv, block_size);

  // Create and Initialize Context
  ctx = EVP_CIPHER_CTX_new();
  if(!EVP_CipherInit(ctx, cipher_fun, key, iv, ENCRYPT))
    handle_errors();

   // Read and incrementally compute the digest
  while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
    if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
      handle_errors();

    if(fwrite(ciphertext, 1, len, f_out) < len) {
      fprintf(stderr,"A Error on updating the output file\n");
      exit(1);
    }
  }

  // Finalize
  if(!EVP_CipherFinal_ex(ctx, ciphertext, &len))
    handle_errors();

  if(fwrite(ciphertext, 1, len, f_out) < len) {
    fprintf(stderr,"Error on updating the output file\n");
    exit(1);
  }

  // Free all
  fclose(f_in);
  fclose(f_out);
  EVP_CIPHER_CTX_free(ctx);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();


  return 0;
}