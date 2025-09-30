#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define GCM_IV_LEN 12 // Do not edit. This must match bot.h defines and is industry standard.
#define GCM_TAG_LEN 16 // Do not edit. This must match bot.h defines and is industry standard.

void handle_crypto_errors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <password> <input_plaintext_file> <output_encrypted_file>\n", argv[0]);
        return 1;
    }

    char *password = argv[1];
    char *in_filename = argv[2];
    char *out_filename = argv[3];

    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) { perror("fopen input"); return 1; }

    fseek(in_file, 0, SEEK_END);
    int plaintext_len = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    unsigned char *plaintext = malloc(plaintext_len);
    fread(plaintext, 1, plaintext_len, in_file);
    fclose(in_file);

    unsigned char key[32];
    EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), NULL, (unsigned char*)password, strlen(password), 1, key, NULL);

    unsigned char iv[GCM_IV_LEN];
    RAND_bytes(iv, sizeof(iv));

    unsigned char tag[GCM_TAG_LEN];
    unsigned char *ciphertext = malloc(plaintext_len);
    int ciphertext_len;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) { perror("fopen output"); return 1; }

    fwrite(iv, 1, sizeof(iv), out_file);
    fwrite(tag, 1, sizeof(tag), out_file);
    fwrite(ciphertext, 1, ciphertext_len, out_file);

    fclose(out_file);
    free(plaintext);
    free(ciphertext);

    printf("Successfully encrypted '%s' to '%s' using AES-256-GCM.\n", in_filename, out_filename);
    return 0;
}
