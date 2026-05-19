/* bot_config_gen.c — standalone encrypted .ircbot.cnf generator
 * Usage: bot_config_gen <outfile> <config_pass> <nick> <server>
 *                       <channel> <admin_name> <mask1> <mask2> <admin_pass>
 *                       [hub_addr] [hub_uuid] [hub_key]
 * Generates new-format named admin records (a|uuid|name|pass|add|0|ts)
 * and usermask records (m|uuid|mask|add|0|ts).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_SIZE          16
#define GCM_IV_LEN         12
#define GCM_TAG_LEN        16
#define PBKDF2_ITERATIONS  100000

static void secure_wipe_local(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

static int write_config(const char *path, const char *pass, const char *plain) {
    int plen = (int)strlen(plain);
    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN], key[32];
    int rc = -1;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *ct = NULL;

    if (RAND_bytes(salt, SALT_SIZE) != 1 ||
        RAND_bytes(iv,   GCM_IV_LEN)  != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_SIZE,
                          PBKDF2_ITERATIONS, EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        return -1;
    }

    ct = malloc((size_t)plen + 16);
    if (!ct) goto done;
    int len, ctlen;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ct, &len, (unsigned char *)plain, plen) != 1) {
        goto done;
    }
    ctlen = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto done;
    ctlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1)
        goto done;

    FILE *f = fopen(path, "wb");
    if (!f) goto done;
    /* 0600: keep the encrypted config readable only by its owner. */
    {
        int fd = fileno(f);
        if (fd >= 0) (void)fchmod(fd, 0600);
    }
    if (fwrite(salt, 1, SALT_SIZE,   f) == SALT_SIZE   &&
        fwrite(iv,   1, GCM_IV_LEN,  f) == GCM_IV_LEN  &&
        fwrite(tag,  1, GCM_TAG_LEN, f) == GCM_TAG_LEN &&
        fwrite(ct,   1, (size_t)ctlen, f) == (size_t)ctlen) {
        rc = 0;
    }
    fclose(f);

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ct) { secure_wipe_local(ct, (size_t)plen); free(ct); }
    secure_wipe_local(key, sizeof(key));
    return rc;
}

static void gen_uuid(char *out, size_t outlen) {
    unsigned char r[16];
    RAND_bytes(r, sizeof(r));
    r[6] = (r[6] & 0x0f) | 0x40;
    r[8] = (r[8] & 0x3f) | 0x80;
    snprintf(out, outlen,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],
             r[8],r[9],r[10],r[11],r[12],r[13],r[14],r[15]);
}

int main(int argc, char *argv[]) {
    if (argc < 10) {
        fprintf(stderr,
            "Usage: %s <file> <cfgpass> <nick> <server> <channel>\n"
            "          <admin_name> <mask1> <mask2> <adminpass> [hub_addr] [hub_uuid] [hub_key]\n",
            argv[0]);
        return 1;
    }
    const char *outfile    = argv[1];
    const char *cfgpass    = argv[2];
    const char *nick       = argv[3];
    const char *server     = argv[4];
    const char *channel    = argv[5];
    const char *adminname  = argv[6];
    const char *mask1      = argv[7];
    const char *mask2      = argv[8];
    const char *adminpass  = argv[9];
    const char *hub_addr   = (argc > 10) ? argv[10] : NULL;
    const char *hub_uuid   = (argc > 11) ? argv[11] : NULL;
    const char *hub_key    = (argc > 12) ? argv[12] : NULL;

    time_t now = time(NULL);
    char admin_uuid[37];
    gen_uuid(admin_uuid, sizeof(admin_uuid));

    char buf[65536];
    int n = 0, rem = (int)sizeof(buf);

#define APP(...) do { int w = snprintf(buf+n, rem, __VA_ARGS__); \
                      if (w>0&&w<rem){n+=w;rem-=w;} } while(0)

    APP("n|%s\n", nick);
    APP("s|%s\n", server);
    APP("c|%s||add|%ld\n", channel, (long)now);
    /* New format admin record: a|uuid|name|pass|add|last_seen|timestamp */
    APP("a|%s|%s|%s|add|0|%ld\n", admin_uuid, adminname, adminpass, (long)now);
    /* New format mask records: m|uuid|mask|add|last_used|timestamp */
    APP("m|%s|%s|add|0|%ld\n", admin_uuid, mask1, (long)now);
    if (mask2 && mask2[0])
        APP("m|%s|%s|add|0|%ld\n", admin_uuid, mask2, (long)now);
    APP("u|ircbot\n");
    APP("g|irc bot\n");
    if (hub_addr && hub_addr[0]) APP("h|%s\n", hub_addr);
    if (hub_key  && hub_key[0])  APP("k|%s\n", hub_key);
    if (hub_uuid && hub_uuid[0]) APP("i|%s\n", hub_uuid);

    if (write_config(outfile, cfgpass, buf) != 0) {
        fprintf(stderr, "Failed to write %s\n", outfile);
        return 1;
    }
    printf("Written: %s  nick=%s  server=%s\n", outfile, nick, server);
    return 0;
}
