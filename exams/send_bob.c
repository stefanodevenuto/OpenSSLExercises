#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define KEY_LENGTH 2048
#define SEED_SIZE 64
#define MAX_BUFFER 1024

void handle_errors() {
	ERR_print_errors_fp(stderr);
	abort();
}

void print_usage(char* filename) {
	printf("Usage: %s filename\n", filename);
}

void print_bytes(unsigned char bytes[], int size) {
  for (int i = 0; i < size; i++)
    printf("%02X ", bytes[i]);
  printf("\n");
}

int main(int argc, char** argv) {
	EVP_PKEY* private_key;
	FILE* f_in;
    RSA* rsa_keypair;
    int ciphertext_lenght;
    int n_read;

    int key_len = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    unsigned char iv[key_len];
    unsigned char key[key_len];
    unsigned char ciphertext[MAX_BUFFER+16];
    unsigned char buffer[MAX_BUFFER];

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	if (argc != 2) {
		print_usage(argv[0]);
		exit(1);
	}

	if((f_in = fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, "Could not open Bob private key");
		exit(1);
	}

	// Generate key pair
    BIGNUM* bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp,RSA_F4); 

    rsa_keypair = RSA_new();
    RSA_generate_key_ex(rsa_keypair, KEY_LENGTH, bn_pub_exp, NULL);

    //////////////////////////////////////////////////////////////////////////////

    // Generate Key and IV
    if(RAND_load_file("/dev/random", SEED_SIZE) != SEED_SIZE)
    	handle_errors();
    RAND_bytes(key, key_len);
    RAND_bytes(iv, key_len);

    //////////////////////////////////////////////////////////////////////////////

    // Encrypt File (AES_128_CBC)
    EVP_CIPHER_CTX* ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    	handle_errors();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, 1))
        handle_errors();

    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        if(!EVP_CipherUpdate(ctx, ciphertext, &ciphertext_lenght, buffer, n_read))
            handle_errors();
    }

    if(!EVP_CipherFinal_ex(ctx, ciphertext, &ciphertext_lenght))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);

    //////////////////////////////////////////////////////////////////////////////

    // Encrypt AES Key with RSA
    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];


    if((encrypted_data_len = RSA_public_encrypt(key_len, key, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
        handle_errors();

    //////////////////////////////////////////////////////////////////////////////

    printf("Encrypted file: ");
    print_bytes(ciphertext, ciphertext_lenght);

    printf("Encrypted key: ");
    print_bytes(encrypted_data, encrypted_data_len);

    RSA_free(rsa_keypair);
    BN_free(bn_pub_exp);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}