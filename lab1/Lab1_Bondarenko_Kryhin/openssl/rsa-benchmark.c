#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark.h"

#define RSA_KEYLEN 2048
#define DATA_SIZE 32

EVP_PKEY *generate_rsa_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    printf("[*] Benchmarking RSA-2048 Key Generation\n");
    benchmark_start();

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_new_id failed.\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_keygen_init failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_set_rsa_keygen_bits failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_keygen failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    benchmark_end();
    benchmark_report();
    printf("\n");

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int main(int argc, char *argv[]) {
    /* Random data to encrypt */
    unsigned char plain_text[DATA_SIZE];
    if (RAND_bytes(plain_text, sizeof(plain_text)) != 1) {
        fprintf(stderr, "[!] Failed to generate random data.\n");
        return 1;
    }

    /* Generate key */
    EVP_PKEY *pkey = generate_rsa_key();
    if (!pkey) {
        fprintf(stderr, "[!] Failed to generate RSA key.\n");
        return 1;
    }

    /* Encryption */
    EVP_PKEY_CTX *ctx_enc = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len;

    ciphertext = malloc(EVP_PKEY_size(pkey));
    if (!ciphertext) {
        fprintf(stderr, "[!] Failed to allocate memory for ciphertext.\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    ctx_enc = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx_enc || EVP_PKEY_encrypt_init(ctx_enc) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_new failed.\n");
        free(ciphertext);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_set_rsa_padding failed.\n");
        free(ciphertext);
        EVP_PKEY_CTX_free(ctx_enc);
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("[*] Benchmarking RSA-2048 Encryption\n");
    benchmark_start();

    ciphertext_len = (size_t)EVP_PKEY_size(pkey);
    if (EVP_PKEY_encrypt(ctx_enc, ciphertext, &ciphertext_len, plain_text,
                         DATA_SIZE) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_encrypt failed.\n");
        free(ciphertext);
        EVP_PKEY_CTX_free(ctx_enc);
        EVP_PKEY_free(pkey);
        return 1;
    }

    benchmark_end();
    benchmark_report();
    printf("\n");

    EVP_PKEY_CTX_free(ctx_enc);

    EVP_PKEY_CTX *ctx_dec = NULL;
    unsigned char *decrypted_text = NULL;
    size_t decrypted_text_len;

    decrypted_text = malloc(EVP_PKEY_size(pkey));
    if (!decrypted_text) {
        fprintf(stderr, "[!] Failed to allocate memory for decrypted text.\n");
        free(ciphertext);
        EVP_PKEY_free(pkey);
        return 1;
    }

    ctx_dec = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx_dec || EVP_PKEY_decrypt_init(ctx_dec) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_new failed.\n");
        free(ciphertext);
        free(decrypted_text);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx_dec, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_CTX_set_rsa_padding failed.\n");
        free(ciphertext);
        free(decrypted_text);
        EVP_PKEY_CTX_free(ctx_dec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("[*] Benchmarking RSA-2048 Decryption\n");
    benchmark_start();

    decrypted_text_len = (size_t)EVP_PKEY_size(pkey);
    if (EVP_PKEY_decrypt(ctx_dec, decrypted_text, &decrypted_text_len,
                         ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "[!] EVP_PKEY_decrypt failed.\n");
        free(ciphertext);
        free(decrypted_text);
        EVP_PKEY_CTX_free(ctx_dec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    benchmark_end();
    benchmark_report();

    if (decrypted_text_len != DATA_SIZE ||
        memcmp(plain_text, decrypted_text, DATA_SIZE) != 0) {
        fprintf(stderr, "[!] Test failed, plaintext wrong.\n");
    }

    free(ciphertext);
    free(decrypted_text);
    EVP_PKEY_CTX_free(ctx_dec);
    EVP_PKEY_free(pkey);

    return 0;
}