#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_SIZE 8

void handle_crypto_errors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <password> <encrypted_file>\n", argv[0]);
    fprintf(stderr, "Example: %s \"my-super-secret-key\" .ircbot\n", argv[0]);
    return 1;
  }

  char *password = argv[1];
  char *in_filename = argv[2];

  FILE *in_file = fopen(in_filename, "rb");
  if (!in_file) {
    perror("Error opening input file");
    return 1;
  }

  // 1. Read the salt from the beginning of the file
  unsigned char salt[SALT_SIZE];
  if (fread(salt, 1, sizeof(salt), in_file) != sizeof(salt)) {
    fprintf(stderr,
            "Error: Could not read salt from file. Is the file corrupt or too "
            "small?\n");
    fclose(in_file);
    return 1;
  }

  // 2. Read the rest of the file as the ciphertext
  fseek(in_file, 0, SEEK_END);
  long ciphertext_len = ftell(in_file) - SALT_SIZE;
  fseek(in_file, SALT_SIZE, SEEK_SET);

  if (ciphertext_len <= 0) {
    fprintf(stderr, "Error: No ciphertext found in file.\n");
    fclose(in_file);
    return 1;
  }

  unsigned char *ciphertext = malloc(ciphertext_len);
  if (!ciphertext) {
    fprintf(stderr, "Error: Malloc failed for ciphertext buffer.\n");
    fclose(in_file);
    return 1;
  }
  fread(ciphertext, 1, ciphertext_len, in_file);
  fclose(in_file);

  // 3. Derive the key and IV from the password and salt
  unsigned char key[32], iv[16];
  if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                     (unsigned char *)password, strlen(password), 1, key,
                     iv) == 0) {
    fprintf(stderr, "Error: Failed to derive key from password.\n");
    handle_crypto_errors();
  }

  // 4. Decrypt the data
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  unsigned char *plaintext =
      malloc(ciphertext_len + 1);  // +1 for null terminator
  if (!plaintext) {
    fprintf(stderr, "Error: Malloc failed for plaintext buffer.\n");
    free(ciphertext);
    return 1;
  }
  int len;
  int plaintext_len;

  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    fprintf(stderr,
            "Error: Decryption failed. This usually means the password is "
            "incorrect.\n");
    handle_crypto_errors();
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    fprintf(stderr,
            "Error: Decryption failed at final block (padding check). The "
            "password is most likely incorrect.\n");
    handle_crypto_errors();
  }
  plaintext_len += len;
  plaintext[plaintext_len] = '\0';  // Null-terminate the decrypted string

  // 5. Clean up and print the result
  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);

  printf("%s", plaintext);

  free(plaintext);
  return 0;
}
