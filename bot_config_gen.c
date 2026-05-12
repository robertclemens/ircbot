/* bot_config_gen.c — standalone encrypted .ircbot.cnf generator
 * Usage: bot_config_gen <outfile> <config_pass> <nick> <server>
 *                       <channel> <mask1> <mask2> <admin_pass>
 *                       [hub_addr] [hub_uuid] [hub_key]
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_SIZE   16
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16

static int write_config(const char *path, const char *pass, const char *plain) {
    int plen = (int)strlen(plain);
    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN], key[32];
    RAND_bytes(salt, SALT_SIZE);
    RAND_bytes(iv,   GCM_IV_LEN);
    EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                   (unsigned char *)pass, (int)strlen(pass), 1, key, NULL);

    unsigned char *ct = malloc((size_t)plen + 16);
    if (!ct) return -1;
    int len, ctlen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, (unsigned char *)plain, plen);
    ctlen = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); ctlen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    FILE *f = fopen(path, "wb");
    if (!f) { free(ct); return -1; }
    fwrite(salt, 1, SALT_SIZE,   f);
    fwrite(iv,   1, GCM_IV_LEN,  f);
    fwrite(tag,  1, GCM_TAG_LEN, f);
    fwrite(ct,   1, ctlen,       f);
    fclose(f);
    free(ct);
    memset(key, 0, sizeof(key));
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 9) {
        fprintf(stderr,
            "Usage: %s <file> <cfgpass> <nick> <server> <channel>\n"
            "          <mask1> <mask2> <adminpass> [hub_addr] [hub_uuid] [hub_key]\n",
            argv[0]);
        return 1;
    }
    const char *outfile    = argv[1];
    const char *cfgpass    = argv[2];
    const char *nick       = argv[3];
    const char *server     = argv[4];
    const char *channel    = argv[5];
    const char *mask1      = argv[6];
    const char *mask2      = argv[7];
    const char *adminpass  = argv[8];
    const char *hub_addr   = (argc > 9)  ? argv[9]  : NULL;
    const char *hub_uuid   = (argc > 10) ? argv[10] : NULL;
    const char *hub_key    = (argc > 11) ? argv[11] : NULL;

    time_t now = time(NULL);
    char buf[65536];
    int n = 0, rem = (int)sizeof(buf);

#define APP(...) do { int w = snprintf(buf+n, rem, __VA_ARGS__); \
                      if (w>0&&w<rem){n+=w;rem-=w;} } while(0)

    APP("n|%s\n", nick);
    APP("s|%s\n", server);
    APP("c|%s||add|%ld\n", channel, (long)now);
    APP("m|%s|add|%ld\n", mask1, (long)now);
    if (mask2 && mask2[0])
        APP("m|%s|add|%ld\n", mask2, (long)now);
    APP("a|%s|%ld\n", adminpass, (long)now);
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
