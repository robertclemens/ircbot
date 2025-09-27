#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bot.h"

int crypto_aes_encrypt_decrypt(bool encrypt, const char *password,
                               const unsigned char *data, int data_len,
                               unsigned char **output) {
  unsigned char key[32], iv[16];
  unsigned char salt[SALT_SIZE];

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;

  if (encrypt) {
    RAND_bytes(salt, sizeof(salt));
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                   (const unsigned char *)password, strlen(password), 1, key,
                   iv);
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, 1);

    int output_len = data_len + 16 + SALT_SIZE;
    *output = malloc(output_len);
    if (!*output) {
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    memcpy(*output, salt, SALT_SIZE);

    int len1 = 0, len2 = 0;
    EVP_CipherUpdate(ctx, (*output) + SALT_SIZE, &len1, data, data_len);
    EVP_CipherFinal_ex(ctx, (*output) + SALT_SIZE + len1, &len2);

    EVP_CIPHER_CTX_free(ctx);
    return SALT_SIZE + len1 + len2;

  } else {
    memcpy(salt, data, SALT_SIZE);
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                   (const unsigned char *)password, strlen(password), 1, key,
                   iv);
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, 0);

    const unsigned char *ciphertext = data + SALT_SIZE;
    int ciphertext_len = data_len - SALT_SIZE;

    int output_len = ciphertext_len + 16;
    *output = malloc(output_len);
    if (!*output) {
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    int len1 = 0, len2 = 0;
    EVP_DecryptUpdate(ctx, *output, &len1, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, (*output) + len1, &len2);

    EVP_CIPHER_CTX_free(ctx);
    return len1 + len2;
  }
}
