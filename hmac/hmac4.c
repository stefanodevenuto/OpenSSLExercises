#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void print_usage(char* filename) {
    printf("Usage: %s filename key", filename);
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
    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    unsigned char buffer[MAXBUF];
    EVP_MD_CTX* md;
    FILE* f;
    int n_read;
    int md_len;

    unsigned char key[EVP_MD_size(EVP_sha256())];
    int key_len;

    unsigned char ipad = 0x36;
    unsigned char opad = 0x5C;

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

    if (strlen(argv[2]) > EVP_MD_block_size(EVP_sha256())) {
        // Create and Initialize Context
        md = EVP_MD_CTX_new();
        if(!EVP_DigestInit(md, EVP_sha256()))
            handle_errors();

        // Add the key
        if(!EVP_DigestUpdate(md, argv[2], strlen(argv[2])))
            handle_errors();

        // Finalize
        if(!EVP_DigestFinal_ex(md, key, &key_len))
            handle_errors();

    } else {
        string_to_bytes(argv[2], strlen(argv[2]), key);
        key_len = strlen(argv[2]) / 2;
    }

    unsigned char xored_ipad[key_len];
    unsigned char xored_opad[key_len];

    for(int i = 0; i < key_len; i++) {
        xored_ipad[i] = key[i] ^ ipad;
        xored_opad[i] = key[i] ^ opad;
    }

    // Re-Initialize Context
    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();

    // Add K XOR ipad at the beginning
    if(!EVP_DigestUpdate(md, xored_ipad, key_len))
      handle_errors();

    // Read and incrementally compute the digest
    while((n_read = fread(buffer, 1, MAXBUF, f)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    // Finalize
    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    // Re-Initialize Context
    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();

    // Add K XOR opad at the beginning
    if(!EVP_DigestUpdate(md, xored_opad, key_len))
      handle_errors();

    // Read and incrementally compute the digest
    if(!EVP_DigestUpdate(md, md_value, md_len))
        handle_errors();

    // Finalize
    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    printf("Digest: ");
    print_bytes(md_value, md_len);    

    // Free all
    fclose(f);
    EVP_MD_CTX_free(md);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
