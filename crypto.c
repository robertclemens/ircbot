#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <string.h>

#include "bot.h"

void secure_wipe(void *ptr, size_t len) {
    if (!ptr) return;
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

bool crypto_derive_config_key(const char *password, const unsigned char *salt,
                              unsigned char out_key[32]) {
    if (!password || !salt || !out_key) return false;
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                             salt, SALT_SIZE, PBKDF2_ITERATIONS,
                             EVP_sha256(), 32, out_key) == 1;
}

/* Generate a combined Ed25519 + X25519 keypair (raw 32 + 32 bytes each).
 * priv_out and pub_out must be HUB_KEY_RAW_LEN (64) bytes each.
 * Layout: priv = ed_priv(32) || x_priv(32); pub = ed_pub(32) || x_pub(32). */
bool crypto_generate_combined_keypair(unsigned char priv_out[HUB_KEY_RAW_LEN],
                                       unsigned char pub_out[HUB_KEY_RAW_LEN]) {
    if (!priv_out || !pub_out) return false;
    EVP_PKEY *ep = NULL, *xp = NULL;
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_CTX *xc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,  NULL);
    size_t l = 32;
    bool ok =
        ec && EVP_PKEY_keygen_init(ec) > 0 && EVP_PKEY_keygen(ec, &ep) > 0 &&
        EVP_PKEY_get_raw_private_key(ep, priv_out,      &l) > 0 && l == 32 &&
        EVP_PKEY_get_raw_public_key (ep, pub_out,       &l) > 0 && l == 32 &&
        xc && EVP_PKEY_keygen_init(xc) > 0 && EVP_PKEY_keygen(xc, &xp) > 0 &&
        EVP_PKEY_get_raw_private_key(xp, priv_out + 32, &l) > 0 && l == 32 &&
        EVP_PKEY_get_raw_public_key (xp, pub_out  + 32, &l) > 0 && l == 32;
    if (ep) EVP_PKEY_free(ep);
    if (xp) EVP_PKEY_free(xp);
    if (ec) EVP_PKEY_CTX_free(ec);
    if (xc) EVP_PKEY_CTX_free(xc);
    if (!ok) { secure_wipe(priv_out, HUB_KEY_RAW_LEN); memset(pub_out, 0, HUB_KEY_RAW_LEN); }
    return ok;
}


int crypto_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *salt, size_t salt_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;
    size_t outlen = out_len;
    int ok = (EVP_PKEY_derive_init(ctx) == 1
           && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1
           && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) == 1
           && EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) == 1
           && EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) == 1
           && EVP_PKEY_derive(ctx, out, &outlen) == 1
           && outlen == out_len);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) memset(out, 0, out_len);
    return ok ? 0 : -1;
}

/* AES-256-GCM encrypt with optional Additional Authenticated Data (AAD).
 * Wire: output_buffer = iv(GCM_IV_LEN) || ciphertext.  Returns total written
 * to output_buffer, or -1 on failure. AAD is authenticated under the tag but
 * not encrypted; it travels separately on the wire and the receiver must
 * supply the same bytes to crypto_aes_gcm_decrypt_aad. */
int crypto_aes_gcm_encrypt_aad(const unsigned char *plaintext, int plaintext_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *key,
                                unsigned char *output_buffer,
                                unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len;
    unsigned char iv[GCM_IV_LEN];

    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto err;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    if (aad && aad_len > 0) {
        int dummy;
        /* AAD-only Update: pass NULL output, OpenSSL records it under the tag. */
        if (1 != EVP_EncryptUpdate(ctx, NULL, &dummy, aad, aad_len)) goto err;
    }

    memcpy(output_buffer, iv, GCM_IV_LEN);
    unsigned char *cipher_ptr = output_buffer + GCM_IV_LEN;
    if (1 != EVP_EncryptUpdate(ctx, cipher_ptr, &len, plaintext, plaintext_len)) goto err;
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_ptr + len, &len)) goto err;
    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + GCM_IV_LEN;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int crypto_aes_gcm_decrypt_aad(const unsigned char *input_buffer, int input_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *key, unsigned char *plaintext,
                                unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    unsigned char iv[GCM_IV_LEN];
    if (input_len < GCM_IV_LEN) return -1;
    memcpy(iv, input_buffer, GCM_IV_LEN);
    const unsigned char *ciphertext = input_buffer + GCM_IV_LEN;
    int ciphertext_len = input_len - GCM_IV_LEN;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;
    if (aad && aad_len > 0) {
        int dummy;
        if (!EVP_DecryptUpdate(ctx, NULL, &dummy, aad, aad_len)) goto err;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;
    plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag)) goto err;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        /* Wipe partial unauthenticated output before returning. */
        secure_wipe(plaintext, (size_t)(plaintext_len + len));
        goto err;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

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
    if (ciphertext_len > 0)
        secure_wipe(plaintext, (size_t)ciphertext_len);
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
    if (!b64_text) {
        BIO_free_all(bio);
        return NULL;
    }
    memcpy(b64_text, bufferPtr->data, bufferPtr->length);
    b64_text[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return b64_text;
}

/* Ed25519 detached-signature verification.  pub: 32-byte raw Ed25519 public
 * key; sig: 64-byte signature over msg.  Verification is a public operation,
 * so constant-time handling is not required.  Returns true iff sig is valid. */
bool crypto_ed25519_verify(const unsigned char pub[32],
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char sig[64]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pk) return false;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    bool ok = (md != NULL
            && EVP_DigestVerifyInit(md, NULL, NULL, NULL, pk) == 1  /* md=NULL: Ed25519 is pure */
            && EVP_DigestVerify(md, sig, 64, msg, msg_len) == 1);
    if (md) EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok;
}

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
