#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define SALT_SIZE 8

void handle_crypto_errors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(
        stderr,
        "Usage: %s <password> <input_plaintext_file> <output_encrypted_file>\n",
        argv[0]);
    return 1;
  }

  char *password = argv[1];
  char *in_filename = argv[2];
  char *out_filename = argv[3];

  FILE *in_file = fopen(in_filename, "rb");
  if (!in_file) {
    perror("fopen input");
    return 1;
  }

  fseek(in_file, 0, SEEK_END);
  int in_len = ftell(in_file);
  fseek(in_file, 0, SEEK_SET);

  unsigned char *in_buf = malloc(in_len);
  fread(in_buf, 1, in_len, in_file);
  fclose(in_file);

  unsigned char salt[SALT_SIZE];
  RAND_bytes(salt, sizeof(salt));

  unsigned char key[32], iv[16];
  if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                     (unsigned char *)password, strlen(password), 1, key,
                     iv) == 0) {
    handle_crypto_errors();
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  int out_len = in_len + 16;  // Room for padding
  unsigned char *out_buf = malloc(out_len);
  int len;

  EVP_EncryptUpdate(ctx, out_buf, &len, in_buf, in_len);
  int ciphertext_len = len;

  EVP_EncryptFinal_ex(ctx, out_buf + len, &len);
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  free(in_buf);

  FILE *out_file = fopen(out_filename, "wb");
  if (!out_file) {
    perror("fopen output");
    return 1;
  }

  // Write the salt first, then the encrypted data
  fwrite(salt, 1, sizeof(salt), out_file);
  fwrite(out_buf, 1, ciphertext_len, out_file);

  fclose(out_file);
  free(out_buf);

  printf("Successfully encrypted '%s' to '%s'\n", in_filename, out_filename);
  return 0;
}
