#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void print_bytes(unsigned char* string, int size) {
	for(int i = 0; i < size; i++)
        printf("%02x", string[i]);
    printf("\n");
}

char* process(unsigned char* data, int length, RSA* rsa_priv_key) {
	unsigned char decrypted_data[RSA_size(rsa_priv_key)];
	
	BIGNUM* m = BN_new();
  	BN_CTX* ctx = BN_CTX_new();

  	BIGNUM* c = BN_bin2bn(data, length, NULL);
  	const BIGNUM* n = RSA_get0_n(rsa_priv_key);
  	const BIGNUM* d = RSA_get0_d(rsa_priv_key);

    // m = c^d mod n
  	if (!BN_mod_exp(m, c, d, n, ctx))
    	return NULL;

    //char* message = BN_bn2hex(m);
    //printf("\nStringa manual: %s\n", message);

    printf("M1: ");
	BN_print_fp(stdout, m);

    if(RSA_private_decrypt(length, (unsigned char*) data,
		(unsigned char*) decrypted_data, rsa_priv_key, RSA_PKCS1_OAEP_PADDING) == -1) {

        return NULL;
    }

    //printf("Stringa dec: %s\n", decrypted_data);

  	BIGNUM* sasso = BN_new();
  	BN_bin2bn(decrypted_data, length, sasso);

  	printf("\nM2: ");
	BN_print_fp(stdout, sasso);

	char* message = BN_bn2hex(sasso);
    printf("\nStringa : %s\n", message);
}

int main(int argc, char const *argv[]) {
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char* message = "messaggio";

	BIGNUM* bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    RSA* rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];

    if((encrypted_data_len = RSA_public_encrypt(strlen(message)+1, message, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
		handle_errors();

	printf("Size: %d\n", encrypted_data_len);
	process(encrypted_data, encrypted_data_len, rsa_keypair);

	CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}