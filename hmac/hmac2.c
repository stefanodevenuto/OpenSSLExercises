#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define SIZE 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void print_usage(char* filename) {
    printf("Usage: %s filename hmac", filename);
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
    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    unsigned char key[] = "00112233aabbccdd";
    unsigned char buffer[SIZE];
    EVP_MD_CTX* hmac_ctx;
    size_t hmac_len;
    EVP_PKEY* hkey;
    int n_read;
    FILE* f;

    if (argc < 3) {
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

    // Create and Initialize Context
    hmac_ctx = EVP_MD_CTX_new();
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 16);

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
        handle_errors();

    // Read and incrementally compute the digest
    while((n_read = fread(buffer, 1, SIZE, f)) > 0){
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // Finalize
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    printf("HMAC computed\t(%s): ", argv[1]);
    print_bytes(hmac_value, hmac_len);
    printf("HMAC passed\t(%s): %s\n", argv[1], argv[2]);

    // Cast the given HMAC to a sequence of bytes
    unsigned char hmac_binary[strlen(argv[2])/2];
    string_to_bytes(argv[2], strlen(argv[2]), hmac_binary);

    // Compare the two HMAC values
    if( (hmac_len == (strlen(argv[2])/2)) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0))
        printf("[+] Verification successful\n");
    else
        printf("[-] Verification failed\n");

    // Free all
    fclose(f);
    EVP_MD_CTX_free(hmac_ctx);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}