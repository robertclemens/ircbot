#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "bot.h"

int crypto_aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, unsigned char *ciphertext,
                           unsigned char *tag) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  unsigned char iv[GCM_IV_LEN];

  RAND_bytes(iv, sizeof(iv));

  if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    return -1;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
    return -1;
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return -1;
  ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
  ciphertext_len += len;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
    return -1;

  memcpy(ciphertext - GCM_IV_LEN, iv, GCM_IV_LEN);

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len + GCM_IV_LEN;
}

int crypto_aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *key, unsigned char *plaintext,
                           unsigned char *tag) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  unsigned char iv[GCM_IV_LEN];

  memcpy(iv, ciphertext, GCM_IV_LEN);

  if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return -1;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
    return -1;
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + GCM_IV_LEN,
                         ciphertext_len - GCM_IV_LEN))
    return -1;
  plaintext_len = len;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
    return -1;
  if (1 > EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}
