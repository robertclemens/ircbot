#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GCM_IV_LEN 12 // Do not edit. This must match bot.h defines and is industry standard.
#define GCM_TAG_LEN 16 // Do not edit. This must match bot.h defines and is industry standard.

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

    // 1. Read the IV and Authentication Tag from the beginning of the file
    unsigned char iv[GCM_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];
    if (fread(iv, 1, sizeof(iv), in_file) != sizeof(iv) ||
        fread(tag, 1, sizeof(tag), in_file) != sizeof(tag)) {
        fprintf(stderr, "Error: Could not read IV/Tag. Is the file corrupt or too small?\n");
        fclose(in_file);
        return 1;
    }

    // 2. Read the rest of the file as the ciphertext
    fseek(in_file, 0, SEEK_END);
    long ciphertext_len = ftell(in_file) - GCM_IV_LEN - GCM_TAG_LEN;
    fseek(in_file, GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);

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

    // 3. Derive the key from the password (no salt needed for GCM key derivation here)
    unsigned char key[32];
    if (EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), NULL,
                       (unsigned char *)password, strlen(password), 1, key,
                       NULL) == 0) {
        fprintf(stderr, "Error: Failed to derive key from password.\n");
        handle_crypto_errors();
    }

    // 4. Decrypt the data using GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *plaintext = malloc(ciphertext_len + 1);
    if (!plaintext) {
        fprintf(stderr, "Error: Malloc failed for plaintext buffer.\n");
        free(ciphertext);
        return 1;
    }
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) <= 0) {
        fprintf(stderr, "Error: Decryption failed. The password is incorrect or the file has been tampered with.\n");
        handle_crypto_errors();
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    // 5. Clean up and print the result
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    printf("\n--- Decrypted Content of '%s' ---\n", in_filename);
    printf("%s", plaintext);
    printf("---------------------------------------\n");

    free(plaintext);
    return 0;
}
