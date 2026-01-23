#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
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

char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines in the output
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char *b64_text = (char *)malloc(bufferPtr->length + 1);
    memcpy(b64_text, bufferPtr->data, bufferPtr->length);
    b64_text[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return b64_text;
}

//unsigned char *base64_decode(const char *input, int *out_len) {
//    BIO *bio, *b64;
//    int decodeLen = strlen(input);
//    unsigned char *buffer = (unsigned char *)malloc(decodeLen);
//    memset(buffer, 0, decodeLen);

//    bio = BIO_new_mem_buf(input, -1);
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_push(b64, bio);

//    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
//    *out_len = BIO_read(bio, buffer, decodeLen);

//    BIO_free_all(bio);
//    return buffer;
//}

// working but with debug output
//unsigned char *base64_decode(const char *input, int *out_len) {
//    fprintf(stderr, "[B64] Decoding %zu chars...\n", strlen(input));
//    
//    BIO *b64, *bmem;
//    int len = strlen(input);
//    unsigned char *buffer = (unsigned char *)malloc(len);
//    if (!buffer) {
//        fprintf(stderr, "[B64] ERROR: malloc failed\n");
//        *out_len = 0;
//        return NULL;
//    }
//    
//    memset(buffer, 0, len);
//    b64 = BIO_new(BIO_f_base64());
//    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//    bmem = BIO_new_mem_buf((void *)input, len);
//    bmem = BIO_push(b64, bmem);
//    
//    *out_len = BIO_read(bmem, buffer, len);
//    BIO_free_all(bmem);
//    
//    if (*out_len <= 0) {
//        fprintf(stderr, "[B64] ERROR: BIO_read returned %d\n", *out_len);
//        free(buffer);
//        *out_len = 0;
//        return NULL;
//    }
//    
//    fprintf(stderr, "[B64] Decoded %d bytes from %d input chars\n", *out_len, len);
//    return buffer;
//}

unsigned char *base64_decode(const char *input, int *out_len) {
    BIO *b64, *bmem;
    int len = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(len);
    if (!buffer) {
        *out_len = 0;
        return NULL;
    }
    
    memset(buffer, 0, len);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, len);
    bmem = BIO_push(b64, bmem);
    
    *out_len = BIO_read(bmem, buffer, len);
    BIO_free_all(bmem);
    
    if (*out_len <= 0) {
        free(buffer);
        *out_len = 0;
        return NULL;
    }
    
    return buffer;
}
