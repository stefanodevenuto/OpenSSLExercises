#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void print_bytes(unsigned char* string, int size) {
	for(int i = 0; i < size; i++)
        printf("%02x", string[i]);
    printf("\n");
}

int envelop_MAC(RSA* rsa_keypair, char* message, int message_len, char* key, int keylength, unsigned char** result) {
	EVP_MD_CTX* md = EVP_MD_CTX_new();

	unsigned char first_hash[EVP_MD_size(EVP_sha256())];
	int first_hash_len;
	unsigned char result_hash[EVP_MD_size(EVP_sha256())];
	int result_hash_len;
	int encrypted_data_len;
    unsigned char* encrypted_data = malloc(sizeof(*encrypted_data) * RSA_size(rsa_keypair));

	////////////////////////////////////////////////////////////////// Hashing

	if(!EVP_DigestInit(md, EVP_sha256()))
		return 1;
	if(!EVP_DigestUpdate(md, message, message_len))
		return 1;
	if(!EVP_DigestUpdate(md, key, keylength))
		return 1;
	if(!EVP_DigestFinal(md, first_hash, &first_hash_len))
		return 1;

	printf("[+] First hash: ");
	print_bytes(first_hash, first_hash_len);

	if(!EVP_DigestInit(md, EVP_sha256()))
		return 1;
	if(!EVP_DigestUpdate(md, first_hash, first_hash_len))
		return 1;
	if(!EVP_DigestFinal(md, result_hash, &result_hash_len))
		return 1;

	printf("[+] Second hash: ");
	print_bytes(result_hash, result_hash_len);

	////////////////////////////////////////////////////////////////// RSA Encrypt

    if((encrypted_data_len = RSA_public_encrypt(result_hash_len, result_hash, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
		return 1;

	*result = encrypted_data;
	return 0;
}

int main(int argc, char const *argv[]) {
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    char* message = "messaggio";
    char* key = "chiave";
    unsigned char* result = NULL;

	BIGNUM* bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    RSA* rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();    

	if(envelop_MAC(rsa_keypair, message, strlen(message), key, strlen(key), &result))
		handle_errors();

	printf("[+] Encrypted message: ");
	print_bytes(result, RSA_size(rsa_keypair));

    free(result);
    RSA_free(rsa_keypair);
    BN_free(bne);

	CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}
