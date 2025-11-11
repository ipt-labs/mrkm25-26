#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "benchmark.h"

#define AES_KEYLEN 32
#define AES_IVLEN 16
#define BUF_SIZE 4096
#define ENCRYPTED_FILE "data.enc.bin"
#define DECRYPTED_FILE "data.dec.bin"

int main(int argc, char *argv[]) {
    /* Validate argv */
    if (argc < 2) {
        fprintf(stderr, "[!] Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    const char *input_path = argv[1];

    /* ------------------- ENCRYPTION ------------------- */

    /* Open input/output files */
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        perror("[!] Error opening input file");
        return 1;
    }
    FILE *fout = fopen(ENCRYPTED_FILE, "wb");
    if (!fout) {
        perror("[!] Error creating output file");
        fclose(fin);
        return 1;
    }

    /* Generate random key and IV */
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_IVLEN];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    /* Initialize cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[!] EVP_CIPHER_CTX_new failed\n");
        fclose(fin);
        fclose(fout);
        return 1;
    }

    /* Initialize encryption */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "[!] EncryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }

    unsigned char inbuf[BUF_SIZE];
    unsigned char outbuf[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    /* Start benchmark for encryption */
    printf("[*] Benchmarking AES-256-CBC Encryption\n");
    benchmark_start();

    /* Encrypt */
    while ((inlen = fread(inbuf, 1, BUF_SIZE, fin)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "[!] EncryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin);
            fclose(fout);
            return 1;
        }
        fwrite(outbuf, 1, outlen, fout);
    }

    /* Finalize encryption */
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "[!] EncryptFinal failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }
    fwrite(outbuf, 1, outlen, fout);

    /* End encryption benchmark */
    benchmark_end();
    benchmark_report();
    printf("\n");

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    /* ------------------- DECRYPTION ------------------- */

    /* Open input/output files */
    FILE *fenc = fopen(ENCRYPTED_FILE, "rb");
    if (!fenc) {
        perror("[!] Error opening encrypted file");
        return 1;
    }
    FILE *fdecrypted = fopen(DECRYPTED_FILE, "wb");
    if (!fdecrypted) {
        perror("[!] Error creating decrypted file");
        fclose(fenc);
        return 1;
    }

    /* Initialize cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[!] EVP_CIPHER_CTX_new failed\n");
        fclose(fenc);
        fclose(fdecrypted);
        return 1;
    }

    /* Initialize decryption */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "[!] DecryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fenc);
        fclose(fdecrypted);
        return 1;
    }

    /* Start benchmark for decryption */
    printf("[*] Benchmarking AES-256-CBC Decryption\n");
    benchmark_start();

    /* Decryption */
    while ((inlen = fread(inbuf, 1, BUF_SIZE, fenc)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "[!] DecryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fenc);
            fclose(fdecrypted);
            return 1;
        }
        fwrite(outbuf, 1, outlen, fdecrypted);
    }

    /* Finalize decryption */
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "[!] DecryptFinal failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fenc);
        fclose(fdecrypted);
        return 1;
    }
    fwrite(outbuf, 1, outlen, fdecrypted);

    /* End decryption benchmark */
    benchmark_end();
    benchmark_report();

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);
    fclose(fenc);
    fclose(fdecrypted);
    unlink(ENCRYPTED_FILE);
    unlink(DECRYPTED_FILE);
    return 0;
}
