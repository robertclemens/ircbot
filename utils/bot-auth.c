/* bot-auth.c — standalone helper that builds a v1 (~A1) AES-256-GCM admin
 * command payload for ircbot. The only external dependency is libcrypto
 * (already linked into the bot). No CPAN modules, no Python, no perl/CryptX.
 *
 * Build:   gcc -O2 -Wall -Wextra -o bot-auth bot-auth.c -lcrypto
 * Usage:   BOT_AUTH_PASSWORD='hunter2' ./bot-auth "die"
 *          ./bot-auth "+admin alice s3cret alice!*@trusted.example"   (prompts)
 *          echo 'hunter2' | ./bot-auth -                              (pipe)
 * Output:  "~A1 <base64-blob>\n" to stdout. The blob is
 *          salt(16) || iv(12) || ciphertext(N) || tag(16). Send via:
 *          /quote PRIVMSG <bot_nick> :~A1 <blob>
 *
 * Plaintext under the GCM tag:
 *          <unix_ts>:<nonce>:<command line>
 * Key:     PBKDF2-HMAC-SHA256(password, salt, 100000, 32)
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef _WIN32
#include <termios.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SALT_SIZE         16
#define GCM_IV_LEN        12
#define GCM_TAG_LEN       16
#define KEY_LEN           32
#define PBKDF2_ITERATIONS 100000
#define MAX_PASS_LEN      128
#define MAX_CMD_LEN       512

static void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

#ifdef _WIN32
#include <windows.h>
static int read_password_tty(const char *prompt, char *buf, size_t len) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldmode = 0, newmode = 0;
    int have_mode = GetConsoleMode(h, &oldmode) ? 1 : 0;
    if (have_mode) {
        newmode = oldmode & ~ENABLE_ECHO_INPUT;
        SetConsoleMode(h, newmode);
    }
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    int rc = 0;
    if (fgets(buf, (int)len, stdin) == NULL) rc = -1;
    if (have_mode) SetConsoleMode(h, oldmode);
    fprintf(stderr, "\n");
    if (rc == 0) buf[strcspn(buf, "\r\n")] = '\0';
    return rc;
}
#else
static int read_password_tty(const char *prompt, char *buf, size_t len) {
    int fd = isatty(STDIN_FILENO) ? STDIN_FILENO : open("/dev/tty", 0);
    if (fd < 0) {
        if (fgets(buf, (int)len, stdin) == NULL) return -1;
        buf[strcspn(buf, "\r\n")] = '\0';
        return 0;
    }
    struct termios oldt, newt;
    if (tcgetattr(fd, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fd, TCSANOW, &newt);
    }
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    int rc = 0;
    if (fgets(buf, (int)len, stdin) == NULL) rc = -1;
    if (tcgetattr(fd, &oldt) == 0) tcsetattr(fd, TCSANOW, &oldt);
    fprintf(stderr, "\n");
    if (rc == 0) buf[strcspn(buf, "\r\n")] = '\0';
    return rc;
}
#endif

static char *base64_encode(const unsigned char *input, int length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, mem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char *out = malloc((size_t)bptr->length + 1);
    if (out) {
        memcpy(out, bptr->data, bptr->length);
        out[bptr->length] = '\0';
    }
    BIO_free_all(b64);
    return out;
}

static int gcm_encrypt(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *pt, int pt_len,
                       unsigned char *ct_out, unsigned char *tag_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ct_len = 0;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, pt_len) != 1) goto err;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1) goto err;
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag_out) != 1) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s \"<command line, with args>\"\n"
        "\n"
        "Reads the admin/oper password from $BOT_AUTH_PASSWORD or, if unset,\n"
        "prompts on the controlling tty with echo disabled.  Use '-' as the\n"
        "argument to read both the password and command from stdin (one per\n"
        "line) — useful for non-interactive callers like irssi /exec.\n"
        "\n"
        "Output (one line to stdout):  ~A1 <base64-blob>\n"
        "\n"
        "Send to the bot via:  /quote PRIVMSG <bot_nick> :~A1 <blob>\n",
        argv0);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 2) usage(argv[0]);

    char password[MAX_PASS_LEN] = {0};
    char command[MAX_CMD_LEN]   = {0};
    int rc = 1;

    if (strcmp(argv[1], "-") == 0) {
        /* stdin mode: line 1 = password, line 2 = command. Used by scripts
         * that want to keep the password out of argv and the environment. */
        if (fgets(password, sizeof(password), stdin) == NULL) {
            fprintf(stderr, "Error: failed to read password from stdin\n");
            return 2;
        }
        password[strcspn(password, "\r\n")] = '\0';
        if (fgets(command, sizeof(command), stdin) == NULL) {
            fprintf(stderr, "Error: failed to read command from stdin\n");
            secure_wipe(password, sizeof(password));
            return 2;
        }
        command[strcspn(command, "\r\n")] = '\0';
    } else {
        snprintf(command, sizeof(command), "%s", argv[1]);
        const char *env_pass = getenv("BOT_AUTH_PASSWORD");
        if (env_pass && env_pass[0]) {
            snprintf(password, sizeof(password), "%s", env_pass);
        } else {
            if (read_password_tty("Bot admin password: ",
                                  password, sizeof(password)) != 0) {
                fprintf(stderr, "Error: failed to read password\n");
                return 2;
            }
        }
    }

    if (password[0] == '\0' || command[0] == '\0') {
        fprintf(stderr, "Error: empty password or command\n");
        secure_wipe(password, sizeof(password));
        return 2;
    }

    /* Build random material */
    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN];
    uint64_t nonce;
    if (RAND_bytes(salt, SALT_SIZE) != 1 ||
        RAND_bytes(iv,   GCM_IV_LEN)  != 1 ||
        RAND_bytes((unsigned char *)&nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed\n");
        secure_wipe(password, sizeof(password));
        return 3;
    }
    /* Keep positive in 64-bit signed math used by bot's strtoull -> ring. */
    nonce &= 0x7FFFFFFFFFFFFFFFULL;

    /* Derive key via PBKDF2-HMAC-SHA256 */
    unsigned char key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), KEY_LEN, key) != 1) {
        fprintf(stderr, "Error: PBKDF2 failed\n");
        secure_wipe(password, sizeof(password));
        return 4;
    }
    secure_wipe(password, sizeof(password));

    /* Plaintext: "<unix_ts>:<nonce>:<command>" */
    char plaintext[MAX_CMD_LEN + 64];
    int pt_len = snprintf(plaintext, sizeof(plaintext), "%lld:%llu:%s",
                          (long long)time(NULL),
                          (unsigned long long)nonce, command);
    if (pt_len <= 0 || pt_len >= (int)sizeof(plaintext)) {
        fprintf(stderr, "Error: plaintext too long\n");
        secure_wipe(key, sizeof(key));
        return 5;
    }

    /* GCM encrypt */
    unsigned char ciphertext[MAX_CMD_LEN + 128];
    unsigned char tag[GCM_TAG_LEN];
    int ct_len = gcm_encrypt(key, iv,
                             (unsigned char *)plaintext, pt_len,
                             ciphertext, tag);
    secure_wipe(key, sizeof(key));
    secure_wipe(plaintext, sizeof(plaintext));
    if (ct_len < 0) {
        fprintf(stderr, "Error: GCM encrypt failed\n");
        return 6;
    }

    /* Assemble blob = salt || iv || ciphertext || tag */
    int blob_len = SALT_SIZE + GCM_IV_LEN + ct_len + GCM_TAG_LEN;
    unsigned char *blob = malloc((size_t)blob_len);
    if (!blob) return 7;
    memcpy(blob,                                       salt,       SALT_SIZE);
    memcpy(blob + SALT_SIZE,                           iv,         GCM_IV_LEN);
    memcpy(blob + SALT_SIZE + GCM_IV_LEN,              ciphertext, ct_len);
    memcpy(blob + SALT_SIZE + GCM_IV_LEN + ct_len,     tag,        GCM_TAG_LEN);

    char *b64 = base64_encode(blob, blob_len);
    secure_wipe(blob, (size_t)blob_len);
    free(blob);
    if (!b64) {
        fprintf(stderr, "Error: base64 encode failed\n");
        return 8;
    }

    printf("~A1 %s\n", b64);
    free(b64);
    rc = 0;
    return rc;
}
