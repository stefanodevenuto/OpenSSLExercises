#include <openssl/bn.h>

void send_to_sara(BIGNUM* b);
BIGNUM* receive_from_sara();
void send_to_carl(BIGNUM* b);
BIGNUM* receive_from_carl();

void handle_errors() {
	ERR_print_errors_fp(stderr);
	abort();
}

int main(int argc, char** argv) {
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Setup
    BIGNUM* p = BN_new();
    BIGNUM* g = BN_new();
	BN_CTX* ctx = BN_CTX_new();

	if (!BN_generate_prime_ex(p, 2048, 0, NULL, NULL, NULL)) 
    	handle_errors();

	BN_set_word(g,2);

	/////////////////////////////////////////////////////////////// SARA SIDE

	BIGNUM* secret_sara = BN_new();
	BIGNUM* public_sara = BN_new();
	BIGNUM* public_carl = BN_new();
	BIGNUM* shared_sara = BN_new();

	BIGNUM* p = receive_from_carl();
	BIGNUM* g = receive_from_carl();

	// Compute Secret
	if(!BN_rand(secret_sara, 256, 0, 1))
		handle_errors();

	// Compute Public: g^secret_sara mod p
	if (!BN_mod_exp(public_sara, g, secret_sara, p, ctx))
		handle_errors();

	// Send Public to Carl
	send_to_carl(public_sara);

	// Receive Public from Carl
	public_carl = receive_from_carl();

	// Compute shared key
	if (!BN_mod_exp(shared_sara, public_carl, secret_sara, p, ctx))
		handle_errors();

	/////////////////////////////////////////////////////////////// CARL SIDE

	BIGNUM* secret_carl = BN_new();
	BIGNUM* public_carl = BN_new();
	BIGNUM* public_sara = BN_new();
	BIGNUM* shared_carl = BN_new();

	send_to_sara(p);
	send_to_sara(g);

	// Compute Secret
	if(!BN_rand(secret_carl, 256, 0, 1))
		handle_errors();

	// Compute Public: g^secret_carl mod p
	if (!BN_mod_exp(public_carl, g, secret_carl, p, ctx))
		handle_errors();

	// Send Public to Sara
	send_to_sara(public_carl);

	// Receive Public from Sara
	public_sara = receive_from_sara();

	// Compute shared key
	if (!BN_mod_exp(shared_carl, public_sara, secret_carl, p, ctx))
		handle_errors();

	///////////////////////////////////////////////////////////////

	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
}