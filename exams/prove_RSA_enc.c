#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define LENGTH 32

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char const *argv[]) {
    unsigned char r1[LENGTH];
    unsigned char r2[LENGTH];
    unsigned char key_simm[LENGTH];
    int n_read;
    char* password = "password";

	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    ////////////////////////////////////////////////////////////////// Generate keypair

    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne,RSA_F4))
        handle_errors();
    
    RSA* rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    // Write private to file
    FILE *rsa_private_file = NULL;
	if((rsa_private_file = fopen("private.pem","w")) == NULL) {
		fprintf(stderr,"Couldn't create the private key file.\n");
		abort();
    }

    FILE *rsa_enc_private_file = NULL;
	if((rsa_enc_private_file = fopen("private.enc.pem","w")) == NULL) {
		fprintf(stderr,"Couldn't create the private key file.\n");
		abort();
    }
    
    if(!PEM_write_RSAPrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    if(!PEM_write_RSAPrivateKey(rsa_enc_private_file, rsa_keypair, EVP_aes_256_cbc(), password, strlen(password), NULL, NULL))
        handle_errors();

    fclose(rsa_private_file);
    fclose(rsa_enc_private_file);

    ////////////////////////////////////////////////////////////////// Read ciphertext

    FILE *f_in;
    if((f_in = fopen("private.enc.pem","r")) == NULL) {
		fprintf(stderr,"Couldn't open the input file, try again\n");
		abort();
    }

    // RSA* PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);
    RSA* new_keys = PEM_read_RSAPrivateKey(f_in, NULL, NULL, password);

    FILE *rsa_dec_private_file = NULL;
	if((rsa_dec_private_file = fopen("private.dec.pem","w")) == NULL) {
		fprintf(stderr,"Couldn't create the private key file.\n");
		abort();
    }
    
    if(!PEM_write_RSAPrivateKey(rsa_dec_private_file, new_keys, NULL, NULL, 0, NULL, NULL))
        handle_errors();

    /*unsigned char buffer[1000000];
    printf("Ciphertext: ");
    while((n_read = fread(buffer, 1, 1000000, f_in)) > 0){
        //for(int i = 0; i < n_read; i++)
        	//printf("%02x-", buffer[i]);
    }
    printf("\n");*/

    RSA_free(rsa_keypair);
    BN_free(bne);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}