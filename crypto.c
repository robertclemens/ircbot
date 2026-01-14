#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include "bot.h"

int crypto_aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, unsigned char *output_buffer,
                           unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len;
    unsigned char iv[GCM_IV_LEN];

    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        return -1;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        goto err;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) {
        goto err;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        goto err;
    }

    memcpy(output_buffer, iv, GCM_IV_LEN);

    unsigned char *cipher_ptr = output_buffer + GCM_IV_LEN;

    if (1 != EVP_EncryptUpdate(ctx, cipher_ptr, &len, plaintext, plaintext_len)) {
        goto err;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipher_ptr + len, &len)) {
        goto err;
    }
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) {
        goto err;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len + GCM_IV_LEN;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int crypto_aes_gcm_decrypt(const unsigned char *input_buffer, int input_len,
                           const unsigned char *key, unsigned char *plaintext,
                           unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len;
    unsigned char iv[GCM_IV_LEN];

    if (input_len < GCM_IV_LEN) {
        return -1;
    }

    memcpy(iv, input_buffer, GCM_IV_LEN);

    const unsigned char *ciphertext = input_buffer + GCM_IV_LEN;
    int ciphertext_len = input_len - GCM_IV_LEN;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        goto err;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) {
        goto err;
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        goto err;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        goto err;
    }
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag)) {
        goto err;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        goto err;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}
