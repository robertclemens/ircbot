#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ==========================================================================
 * Passwordless transport primitives (docs: irchub/docs/passwordless.md).
 * ========================================================================== */

/* X25519(priv, peer_pub) -> out[32].  Fails on an all-zero result, which is
 * what a low-order peer point produces: such a secret is known to anyone and
 * must never key a cipher. */
bool crypto_x25519_derive(const unsigned char priv[32],
                          const unsigned char peer_pub[32],
                          unsigned char out[32]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *pp = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = pk ? EVP_PKEY_CTX_new(pk, NULL) : NULL;
    size_t len = 32;
    bool ok = (pp && ctx
            && EVP_PKEY_derive_init(ctx) == 1
            && EVP_PKEY_derive_set_peer(ctx, pp) == 1
            && EVP_PKEY_derive(ctx, out, &len) == 1
            && len == 32);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pk) EVP_PKEY_free(pk);
    if (pp) EVP_PKEY_free(pp);
    if (ok) {
        unsigned char acc = 0;
        for (int i = 0; i < 32; i++) acc |= out[i];
        ok = (acc != 0);
    }
    if (!ok) secure_wipe(out, 32);
    return ok;
}

/* Combined public key (ed_pub || x_pub) from a combined private key
 * (ed_priv || x_priv). */
bool crypto_combined_pub_from_priv(const unsigned char priv[HUB_KEY_RAW_LEN],
                                   unsigned char pub[HUB_KEY_RAW_LEN]) {
    EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32);
    EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv + 32, 32);
    size_t l1 = 32, l2 = 32;
    bool ok = (ep && xp
            && EVP_PKEY_get_raw_public_key(ep, pub, &l1) == 1 && l1 == 32
            && EVP_PKEY_get_raw_public_key(xp, pub + 32, &l2) == 1 && l2 == 32);
    if (ep) EVP_PKEY_free(ep);
    if (xp) EVP_PKEY_free(xp);
    if (!ok) memset(pub, 0, HUB_KEY_RAW_LEN);
    return ok;
}

/* Strict decode of an 88-char combined public key.  Accepts only the
 * canonical base64 of exactly 64 bytes (so one key has one spelling, which
 * is what uniqueness checks and pin files compare) and rejects a half that is
 * all zero.  Returns false and zeroes out on any deviation. */
bool crypto_pubkey_b64_decode(const char *b64, unsigned char out[HUB_KEY_RAW_LEN]) {
    memset(out, 0, HUB_KEY_RAW_LEN);
    if (!b64 || strlen(b64) != COMBINED_KEY_B64) return false;
    for (int i = 0; i < COMBINED_KEY_B64; i++) {
        char c = b64[i];
        bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (i >= COMBINED_KEY_B64 - 2 ? c != '=' : !alpha) return false;
    }
    int n = 0;
    unsigned char *dec = base64_decode(b64, &n);
    if (!dec || n != HUB_KEY_RAW_LEN) { free(dec); return false; }
    char *re = base64_encode(dec, n);
    bool ok = re && strcmp(re, b64) == 0;
    free(re);
    if (ok) {
        unsigned char a = 0, b = 0;
        for (int i = 0; i < 32; i++) { a |= dec[i]; b |= dec[32 + i]; }
        ok = (a != 0 && b != 0);
    }
    if (ok) memcpy(out, dec, HUB_KEY_RAW_LEN);
    free(dec);
    return ok;
}

/* "ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64).  Shown wherever a
 * key is displayed so humans can compare keys across bot/hub/client. */
void crypto_key_fingerprint(const unsigned char pub[HUB_KEY_RAW_LEN],
                            char out[KEY_FP_LEN + 1]) {
    unsigned char h[32];
    unsigned int hl = 0;
    if (EVP_Digest(pub, HUB_KEY_RAW_LEN, h, &hl, EVP_sha256(), NULL) != 1 || hl != 32) {
        snprintf(out, KEY_FP_LEN + 1, "????:????:????:????");
        return;
    }
    snprintf(out, KEY_FP_LEN + 1, "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
}

/* key = HKDF-SHA256(ikm, salt = eph_pub, info = label || [s_x_pub] || r_x_pub) */
static bool seal_kdf(const unsigned char *ikm, size_t ikm_len,
                     const unsigned char eph_pub[32], const char *label,
                     const unsigned char *s_x_pub, const unsigned char r_x_pub[32],
                     unsigned char key[32]) {
    unsigned char info[64 + 32 + 32];
    size_t ll = strlen(label);
    if (ll > 64) return false;
    size_t il = 0;
    memcpy(info, label, ll); il += ll;
    if (s_x_pub) { memcpy(info + il, s_x_pub, 32); il += 32; }
    memcpy(info + il, r_x_pub, 32); il += 32;
    return crypto_hkdf_sha256(ikm, ikm_len, eph_pub, 32, info, il, key, 32) == 0;
}

/* Seal pt to a recipient X25519 key.  frame = eph_pub(32) || iv(12) || ct ||
 * tag(16).  With a sender key the static term X(s_x_priv, r_x_pub) is mixed
 * in, so only the holder of s_x_priv (or the recipient) can make a frame
 * that opens: that is the sender authentication for ~A2 and ~B2.  With
 * s_x_priv == NULL the frame is anonymous (the ~A2K lockbox).  Returns the
 * frame length, or -1. */
int crypto_seal(const unsigned char *s_x_priv, const unsigned char *s_x_pub,
                const unsigned char r_x_pub[32], const char *label,
                const unsigned char *aad, size_t aad_len,
                const unsigned char *pt, size_t pt_len,
                unsigned char *out, size_t out_cap) {
    if ((s_x_priv == NULL) != (s_x_pub == NULL)) return -1;
    if (pt_len > SEAL_MAX_PLAINTEXT || out_cap < pt_len + SEAL_OVERHEAD) return -1;

    unsigned char eph_priv[32], eph_pub[32], ikm[64], key[32];
    size_t ikm_len = 32;
    int ret = -1;
    EVP_PKEY *ek = NULL;
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t l1 = 32, l2 = 32;
    if (!kc || EVP_PKEY_keygen_init(kc) != 1 || EVP_PKEY_keygen(kc, &ek) != 1 ||
        EVP_PKEY_get_raw_private_key(ek, eph_priv, &l1) != 1 || l1 != 32 ||
        EVP_PKEY_get_raw_public_key(ek, eph_pub, &l2) != 1 || l2 != 32)
        goto out;
    if (!crypto_x25519_derive(eph_priv, r_x_pub, ikm)) goto out;
    if (s_x_priv) {
        if (!crypto_x25519_derive(s_x_priv, r_x_pub, ikm + 32)) goto out;
        ikm_len = 64;
    }
    if (!seal_kdf(ikm, ikm_len, eph_pub, label, s_x_pub, r_x_pub, key)) goto out;

    memcpy(out, eph_pub, 32);
    unsigned char tag[GCM_TAG_LEN];
    int n = crypto_aes_gcm_encrypt_aad(pt, (int)pt_len, aad, (int)aad_len, key,
                                       out + 32, tag);
    if (n != (int)pt_len + GCM_IV_LEN) goto out;
    memcpy(out + 32 + n, tag, GCM_TAG_LEN);
    ret = 32 + n + GCM_TAG_LEN;
out:
    if (ek) EVP_PKEY_free(ek);
    if (kc) EVP_PKEY_CTX_free(kc);
    secure_wipe(eph_priv, sizeof(eph_priv));
    secure_wipe(ikm, sizeof(ikm));
    secure_wipe(key, sizeof(key));
    return ret;
}

/* Inverse of crypto_seal.  s_x_pub selects the expected sender (NULL for an
 * anonymous frame).  Returns the plaintext length, or -1 on any failure
 * (malformed frame, bad point, wrong key, wrong AAD, tampering).  pt_out is
 * wiped on failure. */
int crypto_open(const unsigned char r_x_priv[32], const unsigned char r_x_pub[32],
                const unsigned char *s_x_pub, const char *label,
                const unsigned char *aad, size_t aad_len,
                const unsigned char *frame, size_t frame_len,
                unsigned char *pt_out, size_t pt_cap) {
    return crypto_open_rk(r_x_priv, r_x_pub, s_x_pub, label, aad, aad_len,
                          frame, frame_len, pt_out, pt_cap, NULL, NULL);
}

int crypto_open_rk(const unsigned char r_x_priv[32], const unsigned char r_x_pub[32],
                   const unsigned char *s_x_pub, const char *label,
                   const unsigned char *aad, size_t aad_len,
                   const unsigned char *frame, size_t frame_len,
                   unsigned char *pt_out, size_t pt_cap,
                   const char *rk_label, unsigned char rk_out[32]) {
    if ((rk_label == NULL) != (rk_out == NULL) || (rk_label && !s_x_pub))
        return -1;
    if (frame_len < SEAL_OVERHEAD) return -1;
    size_t ct_len = frame_len - SEAL_OVERHEAD;
    if (ct_len > SEAL_MAX_PLAINTEXT || ct_len > pt_cap) return -1;

    unsigned char ikm[64], key[32], tag[GCM_TAG_LEN];
    size_t ikm_len = 32;
    int ret = -1;
    const unsigned char *eph_pub = frame;
    if (!crypto_x25519_derive(r_x_priv, eph_pub, ikm)) goto out;
    if (s_x_pub) {
        if (!crypto_x25519_derive(r_x_priv, s_x_pub, ikm + 32)) goto out;
        ikm_len = 64;
    }
    if (!seal_kdf(ikm, ikm_len, eph_pub, label, s_x_pub, r_x_pub, key)) goto out;
    memcpy(tag, frame + frame_len - GCM_TAG_LEN, GCM_TAG_LEN);
    ret = crypto_aes_gcm_decrypt_aad(frame + 32, (int)(GCM_IV_LEN + ct_len),
                                     aad, (int)aad_len, key, pt_out, tag);
    if (ret != (int)ct_len) {
        if (ct_len) secure_wipe(pt_out, ct_len);
        ret = -1;
    } else if (rk_label &&
               !seal_kdf(ikm, ikm_len, eph_pub, rk_label, s_x_pub, r_x_pub,
                         rk_out)) {
        secure_wipe(pt_out, ct_len);
        secure_wipe(rk_out, 32);
        ret = -1;
    }
out:
    secure_wipe(ikm, sizeof(ikm));
    secure_wipe(key, sizeof(key));
    return ret;
}

int crypto_reply_seal(const unsigned char key[32], const unsigned char *aad,
                      size_t aad_len, const unsigned char *pt, size_t pt_len,
                      unsigned char *out, size_t out_cap) {
    if (pt_len > A2R_PT_MAX || out_cap < pt_len + A2R_OVERHEAD) return -1;
    unsigned char tag[GCM_TAG_LEN];
    int n = crypto_aes_gcm_encrypt_aad(pt, (int)pt_len, aad, (int)aad_len, key,
                                       out, tag);
    if (n != (int)pt_len + GCM_IV_LEN) return -1;
    memcpy(out + n, tag, GCM_TAG_LEN);
    return n + GCM_TAG_LEN;
}

int crypto_reply_open(const unsigned char key[32], const unsigned char *aad,
                      size_t aad_len, const unsigned char *frame,
                      size_t frame_len, unsigned char *pt_out, size_t pt_cap) {
    if (frame_len < A2R_OVERHEAD) return -1;
    size_t ct_len = frame_len - A2R_OVERHEAD;
    if (ct_len > A2R_PT_MAX || ct_len > pt_cap) return -1;
    unsigned char tag[GCM_TAG_LEN];
    memcpy(tag, frame + frame_len - GCM_TAG_LEN, GCM_TAG_LEN);
    int n = crypto_aes_gcm_decrypt_aad(frame, (int)(GCM_IV_LEN + ct_len), aad,
                                       (int)aad_len, key, pt_out, tag);
    if (n != (int)ct_len) {
        if (ct_len) secure_wipe(pt_out, ct_len);
        return -1;
    }
    return n;
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
