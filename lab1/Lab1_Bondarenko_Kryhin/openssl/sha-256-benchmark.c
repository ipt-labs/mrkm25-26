#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

#include "benchmark.h"

#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    /* Parse argv */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];

    /* Open target file */
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    /* Initialize context */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        fclose(file);
        return 1;
    }

    /* Initialize SHA-256 */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 1;
    }

    /* Start benchmark */
    printf("[*] Benchmarking SHA-256 hashing\n");
    benchmark_start();

    /* Calculate hash */
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 1;
        }
    }

    /* Finalize hash */
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 1;
    }

    /* End benchmark */
    benchmark_end();

    /* Print benchmark report */
    benchmark_report();

    /* Cleanup */
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return 0;
}
