#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024
#define ENCRYPT 1
#define DECRYPT 0

enum args{FILE_IN = 1, ALGO, KEY, IV, FILE_OUT};

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

void print_usage(char* filename) {
  printf("Usage: %s filename algorithm key iv filename_out", filename);
}

void print_bytes(unsigned char bytes[], int n) {
  for (int i = 0; i < n; i++)
    printf("%02x", bytes[i]);
  printf("\n");
}

void string_to_bytes(char* filename, int size, unsigned char result[]) {
    for(int i = 0; i < size/2;i++)
        sscanf(&filename[2*i],"%2hhx", &result[i]);
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

  if (argc < 6) {
    fprintf(stderr, "Missing parameter\n");
    print_usage(argv[FILE_IN]);
    return 1;
  }

  // Recover the proper EVP_CIPHER if existent
  if ((cipher_fun = EVP_get_cipherbyname(argv[ALGO])) == NULL) {
    fprintf(stderr, "Inexistent algorithm");
    return 1;
  }

  // Open the input file
  if((f_in = fopen(argv[FILE_IN],"rb")) == NULL) {
    fprintf(stderr,"Error on opening the input file\n");
    exit(1);
  }

  // Open the output file
  if((f_out = fopen(argv[FILE_OUT],"w")) == NULL) {
    fprintf(stderr,"Error on opening the output file\n");
    exit(1);
  }

  block_size = EVP_CIPHER_block_size(cipher_fun);
  unsigned char key[block_size];
  unsigned char iv[block_size];
  unsigned char plaintext[MAXBUF + block_size];

  // Cast key and IV to bytes
  if(strlen(argv[KEY])/2 != block_size || strlen(argv[IV])/2 != block_size) {
    fprintf(stderr,"Key or IV size not correct: %d, %d != %d\n", strlen(argv[KEY]), strlen(argv[IV]), block_size);
    exit(1);
  }

  unsigned char key_binary[strlen(argv[KEY])/2];
  unsigned char iv_binary[strlen(argv[IV])/2];
  string_to_bytes(argv[KEY], strlen(argv[KEY]), key_binary);
  string_to_bytes(argv[IV], strlen(argv[IV]), iv_binary);

  // Create and Initialize Context
  ctx = EVP_CIPHER_CTX_new();
  if(!EVP_CipherInit(ctx, cipher_fun, key_binary, iv_binary, DECRYPT))
    handle_errors();

  // Read and incrementally complete the decipher process
  while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
    if(!EVP_CipherUpdate(ctx, plaintext, &len, buffer, n_read))
      handle_errors();

    if(fwrite(plaintext, 1, len, f_out) < len) {
      fprintf(stderr,"A Error on updating the output file\n");
      exit(1);
    }
  }

  // Finalize
  if(!EVP_CipherFinal_ex(ctx, plaintext, &len))
    handle_errors();

  if(fwrite(plaintext, 1, len, f_out) < len) {
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