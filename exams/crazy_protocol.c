// 1. generate rand1 and rand2 128bit
// 2. k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
// 3. k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
// 4. symmetric encrypt k2 with k1, generate enc_k2
// 5. generate RSA keypair 2048bit modulus
// 6. encrypt enc_k2 with RSA public

#include <openssl/bn.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char const *argv[]) {
	BIGNUM* rand1 = BN_new();
	BIGNUM* rand2 = BN_new();
	BIGNUM* mod = BN_new();
	BIGNUM* base = BN_new();
	BIGNUM* exponent = BN_new();

	BIGNUM* k1 = BN_new();
	BIGNUM* k2 = BN_new();
	BIGNUM* sum_rand = BN_new();
	BIGNUM* diff_rand = BN_new();
	BIGNUM* mul_rand = BN_new();
	BIGNUM* div = BN_new();
	BIGNUM* rem = BN_new();

	BN_CTX* ctx = BN_CTX_new();

	unsigned char iv[EVP_CIPHER_block_size(EVP_aes_256_cbc())];
	unsigned char key[32];

	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

	////////////////////////////////////////////////////////////////// Setup

  	BN_set_word(base, 2);
  	BN_set_word(exponent, 128);
	BN_exp(mod, base, exponent, ctx);

	////////////////////////////////////////////////////////////////// Generate Randoms

  	BN_rand(rand1, 128, 0, 1);
  	BN_rand(rand2, 128, 0, 1);

  	////////////////////////////////////////////////////////////////// Calculate Ks

  	BN_add(sum_rand, rand1, rand2);
  	BN_sub(diff_rand, rand1, rand2);
  	BN_mul(mul_rand, rand1, rand2, ctx);
  	BN_div(div, rem, mul_rand, diff_rand, ctx);  	

  	BN_mod_mul(k1, sum_rand, diff_rand, mod, ctx);
  	BN_mod(k2, div, mod, ctx);

  	BN_free(rand1);
	BN_free(rand2);
	BN_free(mod);
	BN_free(base);
	BN_free(exponent);
	BN_free(sum_rand);
	BN_free(diff_rand);
	BN_free(mul_rand);
	BN_free(div);
	BN_free(rem);
	BN_CTX_free(ctx);

  	////////////////////////////////////////////////////////////////// Encrypt k2

  	if(RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if(!RAND_bytes(iv, EVP_CIPHER_block_size(EVP_aes_256_cbc())))
        handle_errors();

    EVP_CIPHER_CTX* enc_ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(enc_ctx,EVP_aes_256_cbc(), BN_bn2hex(k1), iv, 1))
        handle_errors();

    int update_len, final_len;
    int ciphertext_len=0;

    char* plaintext = BN_bn2hex(k2);
    unsigned char enc_k2[strlen(plaintext)];

    if(!EVP_CipherUpdate(enc_ctx, enc_k2, &update_len, plaintext, strlen(plaintext)))
        handle_errors();

    ciphertext_len += update_len;
    if(!EVP_CipherFinal_ex(enc_ctx, enc_k2 + ciphertext_len, &final_len))
        handle_errors();

    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(enc_ctx);
	BN_free(k2);
	BN_free(k1);
    
    ////////////////////////////////////////////////////////////////// RSA Encrypt

    BIGNUM* bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    RSA* rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];

    if((encrypted_data_len = RSA_public_encrypt(ciphertext_len, enc_k2, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
		handle_errors();

    FILE* out = fopen("out.bin", "w");
    if(fwrite(encrypted_data, 1,  RSA_size(rsa_keypair), out) < RSA_size(rsa_keypair))
        handle_errors();
    fclose(out);

    RSA_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

}