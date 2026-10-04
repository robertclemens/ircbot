/* bot-auth.c — command-line client for ircbot's key-based admin/oper protocol
 * (~A2A auth request, ~A2K lockbox, ~A2 / ~A2S sealed command, ~A2R sealed
 * reply).  Also the backend
 * that bot-auth.mrc drives for mIRC (as bot-auth.exe).  Only dependency is
 * libcrypto.  Protocol: irchub/docs/passwordless.md §4; the bot side is
 * ircbot/commands.c (a2_handle_auth / a2_open_command).  Passphrase-protected
 * keys and the key holder: irchub/docs/console.md §9.
 *
 * Build:   gcc -O2 -Wall -Wextra -o bot-auth bot-auth.c -lcrypto
 *          (Windows, MSYS2 MinGW 64-bit:
 *           gcc -O2 -Wall -o bot-auth.exe bot-auth.c -lcrypto -ladvapi32 -static)
 *
 * Usage (keyfile = your <ts>_<name>.private.b64, chmod 600):
 *   bot-auth auth <keyfile> <botnick> <yournick>
 *       -> prints "~A2A <sig> <ts>:<nonce>"; send it:  /msg <botnick> <line>
 *   bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply>
 *                 [--pin <pinfile>]
 *       -> the bot answers the auth with a NOTICE "~A2K <b64>"; pass it here
 *          with the <ts>:<nonce> of the ~A2A you sent.  Prints
 *          "<bot pubkey> <fingerprint>".  With --pin, the bot key is checked
 *          against / recorded in pinfile ("<lc botnick> <pubkey>" lines).
 *   bot-auth cmd <keyfile> <botnick> <yournick> <botpubkey|@file>
 *                [--sealed <replykeyfile>]
 *       -> reads ONE command line from stdin (never argv: ps(1) would show
 *          it) and prints "~A2 <b64>"; send it:  /quote PRIVMSG <bot> :<line>
 *          With --sealed it prints "~A2S <b64>" instead, which asks the bot
 *          to seal its replies, and writes that command's reply key to
 *          replykeyfile (created 0600; delete it when done).
 *   bot-auth reply <replykeyfile> <botnick> <yournick>
 *       -> reads the bot's reply lines (raw IRC lines or just "~A2R <b64>")
 *          from stdin and prints each reply in plaintext.
 *   bot-auth fp <pubkey|file>
 *       -> prints the key fingerprint (compare with the bot's 'status').
 *   bot-auth unlock <keyfile> [--expire <1h|30m|6h|1d|secs|never>]
 *                   [--passphrase-file <f>]
 *       -> asks for the passphrase of an irckey-v2 key and starts the key
 *          holder: a background process that keeps the decrypted key in
 *          locked memory until the expiry (default 1h) and signs / does the
 *          X25519 step for later auth/open/cmd calls over a local channel
 *          only your user can open (a 0600 UNIX socket in a 0700 directory,
 *          peer uid checked; on Windows a named pipe with a current-user-only
 *          DACL).  The private key never leaves it.
 *   bot-auth lock <keyfile>     -> ends the key holder (wipes the key).
 *   bot-auth status <keyfile>   -> "unlocked <secs|never>" or "locked".
 *
 * A passphrase-protected key with no holder running: on a terminal (not on
 * Windows) the passphrase is asked for that one call; otherwise bot-auth
 * prints "bot-auth: LOCKED: ..." and exits 4.
 *
 * Exit status: 0 ok, 1 usage/IO error, 2 crypto/verification failure,
 *              3 pinned key mismatch (possible MITM or a rekeyed bot),
 *              4 the key is locked (run bot-auth unlock).
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* SO_PEERCRED / struct ucred */
#endif
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700 /* realpath */
#endif
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define A2A_LABEL "ircbot-A2A-v1"
#define A2K_LABEL "ircbot-A2K-v1"
#define A2_LABEL  "ircbot-A2-v1"
#define A2S_LABEL "ircbot-A2S-v1"
#define A2R_LABEL "ircbot-A2R-v1"
#define A2R_PT_MAX 264           /* "<seq>:<more>:" + up to 240 bytes of text */
#define KEY_LEN 64               /* ed25519(32) || x25519(32) */
#define KEY_B64 88
#define LOCKBOX_LEN (32 + 12 + KEY_LEN + 16)
#define MAX_LINE 400             /* IRC line budget for the ~A2 text */
#define MAX_CMD 300

static void die(int rc, const char *msg) {
  fprintf(stderr, "bot-auth: %s\n", msg);
  exit(rc);
}

/* ---- small helpers ---------------------------------------------------- */

static int b64enc(const unsigned char *in, int n, char *out, size_t cap) {
  if (cap < (size_t)(4 * ((n + 2) / 3) + 1)) return -1;
  return EVP_EncodeBlock((unsigned char *)out, in, n);
}

/* Strict-ish base64 decode: returns decoded length or -1. */
static int b64dec(const char *in, unsigned char *out, int cap) {
  size_t n = strlen(in);
  if (n == 0 || n % 4 != 0 || (int)(n / 4 * 3) > cap + 2) return -1;
  unsigned char *tmp = malloc(n / 4 * 3 + 1);
  if (!tmp) return -1;
  int len = EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)n);
  if (len < 0) { free(tmp); return -1; }
  if (n >= 1 && in[n - 1] == '=') len--;
  if (n >= 2 && in[n - 2] == '=') len--;
  if (len > cap) { OPENSSL_cleanse(tmp, n / 4 * 3); free(tmp); return -1; }
  memcpy(out, tmp, (size_t)len);
  OPENSSL_cleanse(tmp, n / 4 * 3);
  free(tmp);
  return len;
}

static void lc_copy(char *out, size_t cap, const char *in) {
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++)
    out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] + 32) : in[i];
  out[i] = '\0';
}

static void fingerprint(const unsigned char pub[KEY_LEN], char out[20]) {
  unsigned char h[32];
  unsigned int hl = 0;
  if (EVP_Digest(pub, KEY_LEN, h, &hl, EVP_sha256(), NULL) != 1) {
    snprintf(out, 20, "????:????:????:????");
    return;
  }
  snprintf(out, 20, "%02x%02x:%02x%02x:%02x%02x:%02x%02x", h[0], h[1], h[2],
           h[3], h[4], h[5], h[6], h[7]);
}

/* First line of a file, whitespace-trimmed. */
static bool read_first_line(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  bool ok = fgets(out, (int)cap, f) != NULL;
  fclose(f);
  if (ok) out[strcspn(out, " \t\r\n")] = '\0';
  return ok && out[0];
}

/* X25519 with all-zero-result rejection. */
static bool x25519(const unsigned char priv[32], const unsigned char pub[32],
                   unsigned char out[32]) {
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
  EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
  EVP_PKEY_CTX *c = k ? EVP_PKEY_CTX_new(k, NULL) : NULL;
  size_t l = 32;
  bool ok = p && c && EVP_PKEY_derive_init(c) == 1 &&
            EVP_PKEY_derive_set_peer(c, p) == 1 &&
            EVP_PKEY_derive(c, out, &l) == 1 && l == 32;
  EVP_PKEY_CTX_free(c);
  EVP_PKEY_free(k);
  EVP_PKEY_free(p);
  unsigned char acc = 0;
  for (int i = 0; ok && i < 32; i++) acc |= out[i];
  if (!ok || !acc) { OPENSSL_cleanse(out, 32); return false; }
  return true;
}

static bool hkdf(const unsigned char *ikm, size_t il, const unsigned char *salt,
                 size_t sl, const unsigned char *info, size_t nl,
                 unsigned char out[32]) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  size_t ol = 32;
  bool ok = c && EVP_PKEY_derive_init(c) == 1 &&
            EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_salt(c, salt, (int)sl) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_key(c, ikm, (int)il) == 1 &&
            EVP_PKEY_CTX_add1_hkdf_info(c, info, (int)nl) == 1 &&
            EVP_PKEY_derive(c, out, &ol) == 1 && ol == 32;
  EVP_PKEY_CTX_free(c);
  return ok;
}

static bool gcm(bool enc, const unsigned char key[32], const unsigned char iv[12],
                const unsigned char *aad, size_t al, const unsigned char *in,
                int n, unsigned char *out, unsigned char tag[16]) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int l = 0, f = 0;
  bool ok = c && EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
            EVP_CipherInit_ex(c, NULL, NULL, key, iv, enc) == 1 &&
            EVP_CipherUpdate(c, NULL, &l, aad, (int)al) == 1 &&
            EVP_CipherUpdate(c, out, &l, in, n) == 1;
  if (ok && !enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
  if (ok) ok = EVP_CipherFinal_ex(c, out + l, &f) == 1;
  if (ok && enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
  EVP_CIPHER_CTX_free(c);
  if (!ok) OPENSSL_cleanse(out, (size_t)n);
  return ok;
}

/* label "\0" lc(bot) "\0" lc(me) [ "\0" extra ] */
static size_t context(unsigned char *buf, size_t cap, const char *label,
                      const char *bot, const char *me, const char *extra) {
  char b[64], m[64];
  lc_copy(b, sizeof(b), bot);
  lc_copy(m, sizeof(m), me);
  int n = extra ? snprintf((char *)buf, cap, "%s%c%s%c%s%c%s", label, 0, b, 0, m, 0, extra)
                : snprintf((char *)buf, cap, "%s%c%s%c%s", label, 0, b, 0, m);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

/* ---- passphrase-protected keys (irckey-v2) ----------------------------- */

/* Same format and reader bounds as keygen (irchub/keygen.c): a hostile file
 * can cost at most 128 * r * N = 256 MB before the tag is checked. */
#define IRCKEY_TAG "irckey-v2"
#define IRCKEY_LOG2N_MIN 14
#define IRCKEY_LOG2N_MAX 18
#define IRCKEY_R_MAX 8
#define IRCKEY_P_MAX 4
#define IRCKEY_LINE_MAX 512
#define PASS_MAX 1024
#define EXIT_LOCKED 4
#define EXPIRE_DEFAULT 3600
#define EXPIRE_MAX (366L * 86400)

typedef struct {
  unsigned log2n, r, p;
  unsigned char salt[16], nonce[12], ct[KEY_LEN + 16];
  char aad[IRCKEY_LINE_MAX];
} irckey_t;

static bool is_irckey(const char *line) {
  return strncmp(line, IRCKEY_TAG " ", sizeof(IRCKEY_TAG)) == 0;
}

static bool small_uint(const char *s, unsigned lo, unsigned hi, unsigned *v) {
  if (!*s || strlen(s) > 3) return false;
  unsigned x = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return false;
    x = x * 10 + (unsigned)(*s - '0');
  }
  if (x < lo || x > hi) return false;
  *v = x;
  return true;
}

/* Exactly-n-bytes padded base64. */
static bool b64dec_n(const char *in, unsigned char *out, int n) {
  return strlen(in) == (size_t)(4 * ((n + 2) / 3)) && b64dec(in, out, n) == n;
}

static bool irckey_parse(const char *line, irckey_t *k) {
  char buf[IRCKEY_LINE_MAX], *f[8];
  int nf = 0;
  size_t ll = strlen(line);
  if (ll >= sizeof(buf) || strstr(line, "  ") || (ll && line[ll - 1] == ' ')) return false;
  memcpy(buf, line, ll + 1);
  for (char *t = buf, *sp; t && nf < 9; t = sp ? sp + 1 : NULL) {
    sp = strchr(t, ' ');
    if (sp) *sp = '\0';
    if (nf == 8) return false;
    f[nf++] = t;
  }
  bool ok = nf == 8 && strcmp(f[0], IRCKEY_TAG) == 0 && strcmp(f[1], "scrypt") == 0 &&
            small_uint(f[2], IRCKEY_LOG2N_MIN, IRCKEY_LOG2N_MAX, &k->log2n) &&
            small_uint(f[3], 1, IRCKEY_R_MAX, &k->r) &&
            small_uint(f[4], 1, IRCKEY_P_MAX, &k->p) &&
            b64dec_n(f[5], k->salt, 16) && b64dec_n(f[6], k->nonce, 12) &&
            b64dec_n(f[7], k->ct, KEY_LEN + 16);
  if (ok) {
    size_t al = (size_t)(f[7] - buf) - 1;
    memcpy(k->aad, line, al);
    k->aad[al] = '\0';
  }
  OPENSSL_cleanse(buf, sizeof(buf));
  return ok;
}

static bool irckey_open(const irckey_t *k, const char *pass, size_t plen,
                        unsigned char priv[KEY_LEN]) {
  unsigned char key[32];
  uint64_t n = (uint64_t)1 << k->log2n;
  uint64_t maxmem = 128ULL * k->r * n + (1ULL << 20) + 128ULL * k->r * k->p;
  bool ok = EVP_PBE_scrypt(pass, plen, k->salt, 16, n, k->r, k->p, maxmem, key, 32) == 1 &&
            gcm(false, key, k->nonce, (const unsigned char *)k->aad, strlen(k->aad), k->ct,
                KEY_LEN, priv, (unsigned char *)k->ct + KEY_LEN);
  OPENSSL_cleanse(key, sizeof(key));
  return ok;
}

static void lock_mem(void *p, size_t n) {
#ifdef _WIN32
  (void)VirtualLock(p, n);
#else
  (void)mlock(p, n);
#endif
}

/* One line from the terminal with echo off; its length, or -1 (no
 * terminal, EOF, longer than PASS_MAX). */
#ifdef _WIN32
static int read_secret(const char *prompt, char *buf, size_t cap) {
  HANDLE in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, 0, NULL);
  HANDLE out = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           0, NULL);
  DWORD mode = 0, w = 0;
  if (in == INVALID_HANDLE_VALUE || out == INVALID_HANDLE_VALUE || !GetConsoleMode(in, &mode)) {
    if (in != INVALID_HANDLE_VALUE) CloseHandle(in);
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    return -1;
  }
  SetConsoleMode(in, (mode & ~(DWORD)ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT);
  WriteFile(out, prompt, (DWORD)strlen(prompt), &w, NULL);
  size_t n = 0;
  bool nl = false, too_long = false;
  for (;;) {
    char c;
    DWORD r = 0;
    if (!ReadFile(in, &c, 1, &r, NULL) || r == 0) break;
    if (c == '\n') { nl = true; break; }
    if (c == '\r') continue;
    if (n + 1 < cap && n < PASS_MAX) buf[n++] = c; else too_long = true;
  }
  SetConsoleMode(in, mode);
  WriteFile(out, "\r\n", 2, &w, NULL);
  CloseHandle(in);
  CloseHandle(out);
  buf[n] = '\0';
  if (!nl || too_long) { OPENSSL_cleanse(buf, cap); return -1; }
  return (int)n;
}
#else
static int tty_fd = -1;
static struct termios tty_saved;
static volatile sig_atomic_t tty_echo_off = 0;

static void on_prompt_signal(int sig) {
  if (tty_echo_off) (void)tcsetattr(tty_fd, TCSAFLUSH, &tty_saved);
  _exit(128 + sig);
}

static void put_fd(int fd, const char *s, size_t n) {
  ssize_t r = write(fd, s, n);
  (void)r;
}

static int read_secret(const char *prompt, char *buf, size_t cap) {
  if (tty_fd < 0) tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (tty_fd < 0 || tcgetattr(tty_fd, &tty_saved) != 0) return -1;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_prompt_signal;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT, &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
  (void)sigaction(SIGHUP, &sa, NULL);
  (void)sigaction(SIGQUIT, &sa, NULL);
  struct termios t = tty_saved;
  t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
  t.c_lflag |= ICANON;
  tty_echo_off = 1;
  if (tcsetattr(tty_fd, TCSAFLUSH, &t) != 0) { tty_echo_off = 0; return -1; }
  put_fd(tty_fd, prompt, strlen(prompt));
  size_t n = 0;
  bool nl = false, too_long = false;
  for (;;) {
    char c;
    ssize_t r = read(tty_fd, &c, 1);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    if (c == '\n') { nl = true; break; }
    if (n + 1 < cap && n < PASS_MAX) buf[n++] = c; else too_long = true;
  }
  (void)tcsetattr(tty_fd, TCSAFLUSH, &tty_saved);
  tty_echo_off = 0;
  put_fd(tty_fd, "\n", 1);
  if (n > 0 && buf[n - 1] == '\r') n--;
  buf[n] = '\0';
  if (!nl || too_long) { OPENSSL_cleanse(buf, cap); return -1; }
  return (int)n;
}
#endif

/* A passphrase from the first line of a file only its owner can read. */
static int file_secret(const char *path, char *buf, size_t cap) {
  struct stat st;
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
#ifndef _WIN32
  if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 0077)) {
    fclose(f);
    fprintf(stderr, "bot-auth: %s must be a regular file with mode 0600\n", path);
    return -1;
  }
#else
  (void)st;
#endif
  size_t n = 0;
  int c;
  bool too_long = false;
  while ((c = fgetc(f)) != EOF && c != '\n') {
    if (n + 1 < cap && n < PASS_MAX) buf[n++] = (char)c; else too_long = true;
  }
  fclose(f);
  if (n > 0 && buf[n - 1] == '\r') n--;
  buf[n] = '\0';
  if (too_long) { OPENSSL_cleanse(buf, cap); return -1; }
  return (int)n;
}

/* "1h", "30m", "90s", "2d", "3600", "never" -> seconds (-1 = never);
 * -2 = unreadable. */
static long parse_expire(const char *s) {
  if (strcmp(s, "never") == 0) return -1;
  char *e;
  errno = 0;
  long v = strtol(s, &e, 10);
  if (e == s || v < 0 || errno) return -2;
  long mul = 1;
  if (*e == 's') mul = 1, e++;
  else if (*e == 'm') mul = 60, e++;
  else if (*e == 'h') mul = 3600, e++;
  else if (*e == 'd') mul = 86400, e++;
  if (*e || v > EXPIRE_MAX / mul) return -2;
  return v * mul;
}

/* ---- key material ----------------------------------------------------- */

typedef struct {
  unsigned char priv[KEY_LEN];  /* ed || x (unused when held) */
  unsigned char pub[KEY_LEN];
  bool held;                    /* the key holder does the private-key steps */
  char holder[PATH_MAX];        /* its socket / pipe name */
} userkey_t;

static bool derive_pub(const unsigned char priv[KEY_LEN], unsigned char pub[KEY_LEN]) {
  EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32);
  EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv + 32, 32);
  size_t l1 = 32, l2 = 32;
  bool ok = ep && xp && EVP_PKEY_get_raw_public_key(ep, pub, &l1) == 1 &&
            EVP_PKEY_get_raw_public_key(xp, pub + 32, &l2) == 1;
  EVP_PKEY_free(ep);
  EVP_PKEY_free(xp);
  return ok;
}

static bool ed25519_sign(const unsigned char seed[32], const unsigned char *msg, size_t ml,
                         unsigned char sig[64]) {
  size_t sl = 64;
  EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  bool ok = ep && md && EVP_DigestSignInit(md, NULL, NULL, NULL, ep) == 1 &&
            EVP_DigestSign(md, sig, &sl, msg, ml) == 1 && sl == 64;
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(ep);
  return ok;
}

/* The holder's address for keyfile: a hash of its full path (and, on
 * Windows, the user name) so each key has its own holder. */
static bool holder_name(const char *keyfile, char *out, size_t cap) {
  char full[PATH_MAX + 256];
  unsigned char h[32];
  unsigned int hl = 0;
  char hex[33];
#ifdef _WIN32
  char user[256];
  DWORD ul = sizeof(user);
  if (!_fullpath(full, keyfile, PATH_MAX) || !GetUserNameA(user, &ul)) return false;
  size_t fl = strlen(full);
  snprintf(full + fl, sizeof(full) - fl, "|%s", user);
#else
  if (!realpath(keyfile, full)) return false;
#endif
  if (EVP_Digest(full, strlen(full), h, &hl, EVP_sha256(), NULL) != 1) return false;
  for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
#ifdef _WIN32
  int n = snprintf(out, cap, "\\\\.\\pipe\\bot-auth-%s", hex);
#else
  char dir[256];
  const char *rt = getenv("XDG_RUNTIME_DIR");
  if (rt && rt[0] == '/' && strlen(rt) < 200)
    snprintf(dir, sizeof(dir), "%s/bot-auth", rt);
  else
    snprintf(dir, sizeof(dir), "/tmp/bot-auth-%u", (unsigned)getuid());
  if (mkdir(dir, 0700) != 0 && errno != EEXIST) return false;
  struct stat st;
  /* ours, a real directory, and closed to everyone else */
  if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    fprintf(stderr, "bot-auth: %s is not a private directory of yours\n", dir);
    return false;
  }
  int n = snprintf(out, cap, "%s/%s.sock", dir, hex);
  if (n > 0 && (size_t)n >= sizeof(((struct sockaddr_un *)0)->sun_path)) return false;
#endif
  return n > 0 && (size_t)n < cap;
}

/* Holder wire (one request per connection):
 *   request  op(1) len(2, big-endian) payload(len <= HOLD_MAX)
 *   reply    status(1: 0 ok) len(2) payload
 * ops: 'P' -> the 64-byte public key; 'S' msg -> Ed25519 signature (only of
 * an A2A_LABEL context); 'D' peer(32) -> X25519 shared secret; 'T' -> the
 * seconds left as text ("never"); 'Q' -> ends the holder. */
#define HOLD_MAX 512

#ifdef _WIN32
typedef HANDLE hconn_t;
#define HCONN_NONE INVALID_HANDLE_VALUE
/* Works on both the holder's overlapped pipe and a client's plain handle;
 * each step gives up after 2 s. */
static bool hc_io(hconn_t c, void *buf, size_t n, bool wr) {
  unsigned char *p = buf;
  HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
  bool ok = ev != NULL;
  while (ok && n) {
    OVERLAPPED ov;
    DWORD d = 0;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    ResetEvent(ev);
    BOOL r = wr ? WriteFile(c, p, (DWORD)n, &d, &ov) : ReadFile(c, p, (DWORD)n, &d, &ov);
    if (!r && GetLastError() == ERROR_IO_PENDING) {
      if (WaitForSingleObject(ev, 2000) != WAIT_OBJECT_0) {
        CancelIo(c);
        ok = false;
        break;
      }
      r = GetOverlappedResult(c, &ov, &d, FALSE);
    }
    if (!r || d == 0) { ok = false; break; }
    p += d;
    n -= d;
  }
  if (ev) CloseHandle(ev);
  return ok;
}
static hconn_t hc_connect(const char *name) {
  for (int i = 0; i < 3; i++) {
    HANDLE h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;
    if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeA(name, 2000)) break;
  }
  return HCONN_NONE;
}
static void hc_close(hconn_t c) { CloseHandle(c); }
#else
typedef int hconn_t;
#define HCONN_NONE (-1)
/* sa = the UNIX socket address `name` (holder_name keeps it short enough). */
static bool sun_addr(struct sockaddr_un *sa, const char *name) {
  size_t n = strlen(name);
  memset(sa, 0, sizeof(*sa));
  sa->sun_family = AF_UNIX;
  if (n >= sizeof(sa->sun_path)) return false;
  memcpy(sa->sun_path, name, n + 1);
  return true;
}
static bool hc_io(hconn_t c, void *buf, size_t n, bool wr) {
  unsigned char *p = buf;
  while (n) {
    ssize_t d = wr ? send(c, p, n, MSG_NOSIGNAL) : recv(c, p, n, 0);
    if (d < 0 && errno == EINTR) continue;
    if (d <= 0) return false;
    p += d;
    n -= (size_t)d;
  }
  return true;
}
static hconn_t hc_connect(const char *name) {
  struct sockaddr_un sa;
  if (!sun_addr(&sa, name)) return HCONN_NONE;
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return HCONN_NONE;
  struct timeval tv = {5, 0};
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    close(fd);
    return HCONN_NONE;
  }
  return fd;
}
static void hc_close(hconn_t c) { close(c); }
#endif

/* One request to the holder; the reply payload length, or -1 (no holder,
 * refused, I/O error). */
static int holder_call(const char *name, char op, const void *in, size_t il,
                       unsigned char *out, size_t cap) {
  hconn_t c = hc_connect(name);
  if (c == HCONN_NONE) return -1;
  unsigned char h[3] = {(unsigned char)op, (unsigned char)(il >> 8), (unsigned char)il};
  unsigned char r[3];
  int rc = -1;
  if (il <= HOLD_MAX && hc_io(c, h, 3, true) && (!il || hc_io(c, (void *)in, il, true)) &&
      hc_io(c, r, 3, false)) {
    size_t rl = ((size_t)r[1] << 8) | r[2];
    if (r[0] == 0 && rl <= cap && (!rl || hc_io(c, out, rl, false))) rc = (int)rl;
  }
  hc_close(c);
  return rc;
}

/* Loads keyfile.  A plain key is read directly.  An irckey-v2 key uses a
 * running holder, else (use_holder false, or none running) asks for the
 * passphrase on the terminal — or from passfile — and, failing that, exits
 * EXIT_LOCKED. */
static void load_key_ex(const char *path, userkey_t *k, bool use_holder, const char *passfile) {
  struct stat st;
  memset(k, 0, sizeof(*k));
  if (stat(path, &st) != 0) die(1, "cannot read the key file");
  char line[IRCKEY_LINE_MAX + 2];
  FILE *f = fopen(path, "r");
  if (!f || !fgets(line, sizeof(line), f)) die(1, "cannot read the key file");
  fclose(f);
  line[strcspn(line, "\r\n")] = '\0';
  if (!is_irckey(line)) {
#ifndef _WIN32
    if (st.st_mode & 0077)
      fprintf(stderr, "bot-auth: warning: %s is readable by others — chmod 600 it\n",
              path);
    if (isatty(STDERR_FILENO))
      fprintf(stderr, "bot-auth: warning: %s has no passphrase (add one: keygen --passwd "
                      "%s)\n", path, path);
#endif
    line[strcspn(line, " \t")] = '\0';
    int n = b64dec(line, k->priv, KEY_LEN);
    OPENSSL_cleanse(line, sizeof(line));
    if (n != KEY_LEN)
      die(1, "key file is not an 88-char private key (use the .private.b64)");
    if (!derive_pub(k->priv, k->pub)) die(2, "cannot derive the public key");
    return;
  }
  irckey_t ik;
  if (!irckey_parse(line, &ik)) die(1, "unreadable or out-of-range irckey-v2 key file");
  OPENSSL_cleanse(line, sizeof(line));
  if (use_holder && holder_name(path, k->holder, sizeof(k->holder)) &&
      holder_call(k->holder, 'P', NULL, 0, k->pub, KEY_LEN) == KEY_LEN) {
    k->held = true;
    return;
  }
  char pass[PASS_MAX + 1];
  lock_mem(pass, sizeof(pass));
  bool ok = false;
  for (int tries = 0; tries < (passfile ? 1 : 3) && !ok; tries++) {
    int n;
#ifdef _WIN32
    /* bot-auth.exe runs in mIRC's hidden console: never prompt there */
    n = passfile ? file_secret(passfile, pass, sizeof(pass)) : (use_holder ? -1 :
        read_secret("Passphrase: ", pass, sizeof(pass)));
#else
    n = passfile ? file_secret(passfile, pass, sizeof(pass))
                 : read_secret("Passphrase: ", pass, sizeof(pass));
#endif
    if (n < 0) break;
    ok = irckey_open(&ik, pass, (size_t)n, k->priv);
    OPENSSL_cleanse(pass, sizeof(pass));
    if (!ok) fprintf(stderr, "bot-auth: wrong passphrase (or a damaged key file)\n");
  }
  OPENSSL_cleanse(pass, sizeof(pass));
  OPENSSL_cleanse(&ik, sizeof(ik));
  if (!ok) {
    fprintf(stderr, "bot-auth: LOCKED: %s is passphrase-protected; run: bot-auth unlock %s\n",
            path, path);
    exit(EXIT_LOCKED);
  }
  if (!derive_pub(k->priv, k->pub)) die(2, "cannot derive the public key");
}

static void load_key(const char *path, userkey_t *k) { load_key_ex(path, k, true, NULL); }

/* Ed25519 signature of an A2A context, locally or by the holder. */
static bool key_sign(const userkey_t *k, const unsigned char *msg, size_t ml,
                     unsigned char sig[64]) {
  if (k->held) return holder_call(k->holder, 'S', msg, ml, sig, 64) == 64;
  return ed25519_sign(k->priv, msg, ml, sig);
}

/* X25519(our x key, peer), locally or by the holder. */
static bool key_dh(const userkey_t *k, const unsigned char peer[32], unsigned char out[32]) {
  if (k->held) {
    unsigned char acc = 0;
    if (holder_call(k->holder, 'D', peer, 32, out, 32) != 32) return false;
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc != 0;
  }
  return x25519(k->priv + 32, peer, out);
}

/* A bot public key given inline (88 chars) or as @file. */
static void load_pub(const char *arg, unsigned char pub[KEY_LEN]) {
  char line[256];
  if (arg[0] == '@') {
    if (!read_first_line(arg + 1, line, sizeof(line))) die(1, "cannot read the pubkey file");
  } else if (!read_first_line(arg, line, sizeof(line))) {
    snprintf(line, sizeof(line), "%s", arg);
  }
  if (strlen(line) != KEY_B64 || b64dec(line, pub, KEY_LEN) != KEY_LEN)
    die(1, "not an 88-char public key");
}

static void make_nonce(char out[17]) {
  unsigned char r[8];
  if (RAND_bytes(r, sizeof(r)) != 1) die(2, "RNG failure");
  for (int i = 0; i < 8; i++) snprintf(out + 2 * i, 3, "%02x", r[i]);
}

/* ---- subcommands ------------------------------------------------------ */

static int cmd_auth(const char *keyfile, const char *bot, const char *me) {
  userkey_t k;
  load_key(keyfile, &k);
  char nonce[17], tsn[40];
  make_nonce(nonce);
  snprintf(tsn, sizeof(tsn), "%lld:%s", (long long)time(NULL), nonce);
  unsigned char msg[256];
  size_t ml = context(msg, sizeof(msg), A2A_LABEL, bot, me, tsn);
  unsigned char sig[64];
  bool ok = ml && key_sign(&k, msg, ml, sig);
  OPENSSL_cleanse(&k, sizeof(k));
  if (!ok) die(2, "signing failed");
  char sb[100];
  b64enc(sig, 64, sb, sizeof(sb));
  printf("~A2A %s %s\n", sb, tsn);
  return 0;
}

/* Pin file: "<lc botnick> <pubkey b64>" per line.  0 ok/recorded, 3 mismatch. */
static int pin_check(const char *pinfile, const char *bot,
                     const unsigned char pub[KEY_LEN]) {
  char want[100], lbot[64];
  b64enc(pub, KEY_LEN, want, sizeof(want));
  lc_copy(lbot, sizeof(lbot), bot);
  FILE *f = fopen(pinfile, "r");
  if (f) {
    char line[256];
    while (fgets(line, sizeof(line), f)) {
      char n[64] = {0}, k[128] = {0};
      if (sscanf(line, "%63s %127s", n, k) != 2 || strcmp(n, lbot) != 0) continue;
      fclose(f);
      if (strcmp(k, want) == 0) return 0;
      unsigned char old[KEY_LEN];
      char ofp[20] = "(unreadable)", nfp[20];
      if (b64dec(k, old, KEY_LEN) == KEY_LEN) fingerprint(old, ofp);
      fingerprint(pub, nfp);
      fprintf(stderr,
              "bot-auth: *** KEY CHANGED for %s: pinned %s, offered %s ***\n"
              "bot-auth: possible man-in-the-middle, or the bot was rekeyed.\n"
              "bot-auth: check the bot's 'status' / hub console 'bot list', then remove its "
              "line from %s to accept.\n", bot, ofp, nfp, pinfile);
      return 3;
    }
    fclose(f);
  }
#ifndef _WIN32
  mode_t old = umask(077);
#endif
  f = fopen(pinfile, "a");
#ifndef _WIN32
  umask(old);
#endif
  if (!f) die(1, "cannot write the pin file");
  fprintf(f, "%s %s\n", lbot, want);
  fclose(f);
  return 0;
}

static int cmd_open(const char *keyfile, const char *bot, const char *me,
                    const char *tsn, const char *reply, const char *pinfile) {
  const char *b = strncmp(reply, "~A2K ", 5) == 0 ? reply + 5 : reply;
  unsigned char frame[LOCKBOX_LEN + 4];
  if (b64dec(b, frame, sizeof(frame)) != LOCKBOX_LEN) die(2, "not a ~A2K lockbox");
  userkey_t k;
  load_key(keyfile, &k);
  unsigned char ss[32], key[32], info[64], aad[256], pub[KEY_LEN];
  size_t il = strlen(A2K_LABEL);
  memcpy(info, A2K_LABEL, il);
  memcpy(info + il, k.pub + 32, 32);
  size_t al = context(aad, sizeof(aad), A2K_LABEL, bot, me, tsn);
  bool ok = al && key_dh(&k, frame, ss) &&
            hkdf(ss, 32, frame, 32, info, il + 32, key) &&
            gcm(false, key, frame + 32, aad, al, frame + 44, KEY_LEN, pub,
                frame + 44 + KEY_LEN);
  OPENSSL_cleanse(&k, sizeof(k));
  OPENSSL_cleanse(ss, sizeof(ss));
  OPENSSL_cleanse(key, sizeof(key));
  if (!ok) die(2, "lockbox did not verify (wrong key, bot nick, your nick, or ts:nonce)");
  if (pinfile) {
    int rc = pin_check(pinfile, bot, pub);
    if (rc) return rc;
  }
  char pb[100], fp[20];
  b64enc(pub, KEY_LEN, pb, sizeof(pb));
  fingerprint(pub, fp);
  printf("%s %s\n", pb, fp);
  return 0;
}

/* With rkfile: a ~A2S frame, and its reply key HKDF(ikm, eph_pub, A2R_LABEL ||
 * user_x || bot_x) written to rkfile (0600) for `bot-auth reply`. */
static int cmd_cmd(const char *keyfile, const char *bot, const char *me,
                   const char *botpub, const char *rkfile) {
  const char *label = rkfile ? A2S_LABEL : A2_LABEL;
  unsigned char bpub[KEY_LEN];
  load_pub(botpub, bpub);
  char line_in[MAX_CMD + 2];
  if (!fgets(line_in, sizeof(line_in), stdin)) die(1, "no command on stdin");
  size_t cl = strcspn(line_in, "\r\n");
  if (cl == strlen(line_in) && !feof(stdin)) die(1, "command too long");
  line_in[cl] = '\0';
  if (!cl) die(1, "empty command");
  for (size_t i = 0; i < cl; i++)
    if ((unsigned char)line_in[i] < 0x20 || line_in[i] == 0x7f)
      die(1, "control characters are not allowed in commands");

  userkey_t k;
  load_key(keyfile, &k);
  char nonce[17];
  make_nonce(nonce);
  char pt[MAX_CMD + 64];
  int pl = snprintf(pt, sizeof(pt), "%lld:%s:%s", (long long)time(NULL), nonce,
                    line_in);
  OPENSSL_cleanse(line_in, sizeof(line_in));

  unsigned char eph_priv[32], eph_pub[32], ikm[64], key[32], rk[32], info[96];
  unsigned char aad[160], frame[sizeof(pt) + 60], tag[16];
  EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *ek = NULL;
  size_t l1 = 32, l2 = 32;
  bool ok = kc && EVP_PKEY_keygen_init(kc) == 1 && EVP_PKEY_keygen(kc, &ek) == 1 &&
            EVP_PKEY_get_raw_private_key(ek, eph_priv, &l1) == 1 &&
            EVP_PKEY_get_raw_public_key(ek, eph_pub, &l2) == 1;
  EVP_PKEY_free(ek);
  EVP_PKEY_CTX_free(kc);
  size_t il = strlen(label);
  memcpy(info, label, il);
  memcpy(info + il, k.pub + 32, 32);
  memcpy(info + il + 32, bpub + 32, 32);
  size_t al = context(aad, sizeof(aad), label, bot, me, NULL);
  ok = ok && al && pl > 0 && pl < (int)sizeof(pt) &&
       x25519(eph_priv, bpub + 32, ikm) && key_dh(&k, bpub + 32, ikm + 32) &&
       hkdf(ikm, 64, eph_pub, 32, info, il + 64, key) &&
       RAND_bytes(frame + 32, 12) == 1 &&
       gcm(true, key, frame + 32, aad, al, (unsigned char *)pt, pl, frame + 44, tag);
  if (ok && rkfile) {
    il = strlen(A2R_LABEL);
    memcpy(info, A2R_LABEL, il);
    ok = hkdf(ikm, 64, eph_pub, 32, info, il + 64, rk);
  }
  OPENSSL_cleanse(&k, sizeof(k));
  OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
  OPENSSL_cleanse(ikm, sizeof(ikm));
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(pt, sizeof(pt));
  if (!ok) die(2, "sealing failed");
  memcpy(frame, eph_pub, 32);
  memcpy(frame + 44 + pl, tag, 16);
  int fl = 44 + pl + 16;
  char out[1024];
  if (b64enc(frame, fl, out, sizeof(out)) < 0) die(2, "encoding failed");
  if (strlen(out) + (rkfile ? 5 : 4) > MAX_LINE)
    die(1, "command too long for one IRC line (keep it under ~200 chars)");
  if (rkfile) {
    char rb[64];
    b64enc(rk, 32, rb, sizeof(rb));
    OPENSSL_cleanse(rk, sizeof(rk));
#ifndef _WIN32
    mode_t old = umask(077);
#endif
    FILE *f = fopen(rkfile, "w");
#ifndef _WIN32
    umask(old);
    if (f) (void)fchmod(fileno(f), 0600);
#endif
    bool wrote = f && fprintf(f, "%s\n", rb) > 0;
    if (f && fclose(f) != 0) wrote = false;
    OPENSSL_cleanse(rb, sizeof(rb));
    if (!wrote) die(1, "cannot write the reply key file");
  }
  printf("%s %s\n", rkfile ? "~A2S" : "~A2", out);
  return 0;
}

/* Open the bot's ~A2R replies to one ~A2S command (its reply key in rkfile):
 * "<seq>:<more>:<text>" pieces, seq rising (a repeat is dropped), pieces with
 * more = 1 joined to the next.  Control bytes are shown as '?'.  Exit 2 if any
 * ~A2R line did not open. */
static int cmd_reply(const char *rkfile, const char *bot, const char *me) {
  char line[2048];
  unsigned char rk[32];
  if (!read_first_line(rkfile, line, sizeof(line))) die(1, "cannot read the reply key file");
  int kl = b64dec(line, rk, sizeof(rk));
  OPENSSL_cleanse(line, sizeof(line));
  if (kl != 32) die(1, "not a reply key file (from bot-auth cmd --sealed)");
  unsigned char aad[160];
  size_t al = context(aad, sizeof(aad), A2R_LABEL, bot, me, NULL);
  if (!al) die(1, "bot nick or your nick too long");

  char joined[8192];
  size_t jl = 0;
  unsigned long next = 0;
  bool seen = false;
  int bad = 0;
  while (fgets(line, sizeof(line), stdin)) {
    char *p = strstr(line, "~A2R ");
    if (!p) continue;
    p += 5;
    p[strcspn(p, "\r\n \t")] = '\0';
    unsigned char fr[A2R_PT_MAX + 28 + 4], pt[A2R_PT_MAX + 1];
    int fl = b64dec(p, fr, sizeof(fr));
    int n = fl - 28;
    if (fl < 28 || n > A2R_PT_MAX ||
        !gcm(false, rk, fr, aad, al, fr + 12, n, pt, fr + fl - 16)) {
      fprintf(stderr, "bot-auth: an ~A2R line did not open (a reply to another "
                      "command, or the wrong nicks)\n");
      bad++;
      continue;
    }
    pt[n] = '\0';
    char *e;
    unsigned long seq = strtoul((char *)pt, &e, 10);
    if (e == (char *)pt || e[0] != ':' || (e[1] != '0' && e[1] != '1') || e[2] != ':') {
      OPENSSL_cleanse(pt, sizeof(pt));
      bad++;
      continue;
    }
    if (seen && seq < next) {  /* a repeat of a piece already shown */
      OPENSSL_cleanse(pt, sizeof(pt));
      continue;
    }
    if (seen && seq != next && jl) {  /* a piece went missing */
      printf("%.*s [...]\n", (int)jl, joined);
      jl = 0;
    }
    next = seq + 1;
    seen = true;
    for (char *t = e + 3; *t && jl < sizeof(joined) - 1; t++)
      joined[jl++] = ((unsigned char)*t < 0x20 || *t == 0x7f) ? '?' : *t;
    if (e[1] == '0') {
      printf("%.*s\n", (int)jl, joined);
      jl = 0;
    }
    OPENSSL_cleanse(pt, sizeof(pt));
  }
  if (jl) printf("%.*s [...]\n", (int)jl, joined);
  OPENSSL_cleanse(joined, sizeof(joined));
  OPENSSL_cleanse(rk, sizeof(rk));
  return bad ? 2 : 0;
}

static int cmd_fp(const char *arg) {
  unsigned char pub[KEY_LEN];
  load_pub(arg, pub);
  char fp[20];
  fingerprint(pub, fp);
  printf("%s\n", fp);
  return 0;
}

/* ---- key holder ------------------------------------------------------- */

/* The unlocked key, in locked memory for the holder's lifetime. */
static userkey_t *hold_key;
static const char *hold_name;

/* Answers one request (op, payload) into out; the reply length or -1. */
static int hold_answer(unsigned char op, const unsigned char *in, size_t il,
                       unsigned char *out, time_t deadline, bool *quit) {
  size_t ll = strlen(A2A_LABEL) + 1;
  switch (op) {
  case 'P':
    memcpy(out, hold_key->pub, KEY_LEN);
    return KEY_LEN;
  case 'S': /* only ever an A2A auth context */
    if (il <= ll || memcmp(in, A2A_LABEL, ll) != 0) return -1;
    return ed25519_sign(hold_key->priv, in, il, out) ? 64 : -1;
  case 'D':
    if (il != 32) return -1;
    return x25519(hold_key->priv + 32, in, out) ? 32 : -1;
  case 'T':
    if (!deadline) return snprintf((char *)out, 32, "never");
    return snprintf((char *)out, 32, "%lld",
                    (long long)(deadline > time(NULL) ? deadline - time(NULL) : 0));
  case 'Q':
    *quit = true;
    return 0;
  }
  return -1;
}

/* Reads one request from c, answers it.  false = end the holder. */
static bool hold_serve(hconn_t c, time_t deadline) {
  unsigned char h[3], in[HOLD_MAX], out[64], r[3];
  bool quit = false;
  int n = -1;
  if (hc_io(c, h, 3, false)) {
    size_t il = ((size_t)h[1] << 8) | h[2];
    if (il <= HOLD_MAX && (!il || hc_io(c, in, il, false)))
      n = hold_answer(h[0], in, il, out, deadline, &quit);
  }
  r[0] = n < 0 ? 1 : 0;
  r[1] = 0;
  r[2] = (unsigned char)(n < 0 ? 0 : n);
  if (hc_io(c, r, 3, true) && n > 0) (void)hc_io(c, out, (size_t)n, true);
  OPENSSL_cleanse(in, sizeof(in));
  OPENSSL_cleanse(out, sizeof(out));
  return !quit;
}

static void hold_wipe(void) {
  if (hold_key) OPENSSL_cleanse(hold_key, sizeof(*hold_key));
}

#ifdef _WIN32
/* A pipe only the current user can open. */
static bool user_only_sa(SECURITY_ATTRIBUTES *sa) {
  HANDLE tok;
  unsigned char buf[256];
  DWORD len = 0;
  LPSTR sid = NULL;
  char sddl[300];
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
  BOOL ok = GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len);
  CloseHandle(tok);
  if (!ok || !ConvertSidToStringSidA(((TOKEN_USER *)buf)->User.Sid, &sid)) return false;
  snprintf(sddl, sizeof(sddl), "D:P(A;;GA;;;%s)", sid);
  LocalFree(sid);
  sa->nLength = sizeof(*sa);
  sa->bInheritHandle = FALSE;
  return ConvertStringSecurityDescriptorToSecurityDescriptorA(
             sddl, SDDL_REVISION_1, &sa->lpSecurityDescriptor, NULL) != 0;
}

static int hold_run(time_t deadline) {
  SECURITY_ATTRIBUTES sa;
  if (!user_only_sa(&sa)) { hold_wipe(); die(1, "cannot build the pipe's access list"); }
  HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
  bool first = true;
  printf("unlocked %s until %s", hold_name, deadline ? "" : "you run bot-auth lock\n");
  if (deadline) {
    char tb[64];
    struct tm *tmv = localtime(&deadline);
    strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S\n", tmv);
    printf("%s", tb);
  }
  fflush(stdout);
  for (;;) {
    HANDLE p = CreateNamedPipeA(
        hold_key->holder,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096,
        4096, 0, &sa);
    if (p == INVALID_HANDLE_VALUE) break;
    if (first) FreeConsole(); /* mIRC's unlock window closes; we keep running */
    first = false;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    ResetEvent(ev);
    BOOL c = ConnectNamedPipe(p, &ov);
    DWORD e = GetLastError();
    bool connected = c || e == ERROR_PIPE_CONNECTED;
    if (!connected && e == ERROR_IO_PENDING) {
      DWORD ms = INFINITE;
      if (deadline) {
        time_t now = time(NULL);
        ms = deadline > now ? (DWORD)((deadline - now) * 1000) : 0;
      }
      DWORD t = 0;
      if (WaitForSingleObject(ev, ms) == WAIT_OBJECT_0 && GetOverlappedResult(p, &ov, &t, FALSE))
        connected = true;
      else
        CancelIo(p);
    }
    bool go_on = true;
    if (connected) {
      go_on = hold_serve(p, deadline);
      FlushFileBuffers(p);
      DisconnectNamedPipe(p);
    }
    CloseHandle(p);
    if (!go_on || (deadline && time(NULL) >= deadline)) break;
  }
  hold_wipe();
  LocalFree(sa.lpSecurityDescriptor);
  CloseHandle(ev);
  return 0;
}
#else
static volatile sig_atomic_t hold_stop = 0;
static void on_hold_signal(int sig) { (void)sig; hold_stop = 1; }

/* Only the user who started the holder may talk to it. */
static bool peer_is_me(int fd) {
#if defined(__linux__)
  struct ucred uc;
  socklen_t l = sizeof(uc);
  return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &l) == 0 && uc.uid == getuid();
#else
  uid_t u;
  gid_t g;
  return getpeereid(fd, &u, &g) == 0 && u == getuid();
#endif
}

static int hold_run(time_t deadline) {
  /* a copy: hold_wipe() clears hold_key, path included, before the unlink */
  char name[sizeof(hold_key->holder)];
  snprintf(name, sizeof(name), "%s", hold_key->holder);
  struct sockaddr_un sa;
  int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  (void)unlink(name); /* a stale socket: we checked that no holder answers */
  mode_t old = umask(077);
  bool ok = ls >= 0 && sun_addr(&sa, name) && bind(ls, (struct sockaddr *)&sa, sizeof(sa)) == 0 &&
            chmod(name, 0600) == 0 && listen(ls, 8) == 0;
  umask(old);
  if (!ok) {
    hold_wipe();
    die(1, "cannot create the key holder's socket");
  }
  fflush(stdout);
  pid_t pid = fork();
  if (pid < 0) {
    hold_wipe();
    unlink(name);
    die(1, "fork failed");
  }
  if (pid > 0) { /* the parent: report and leave; the child holds the key */
    hold_wipe();
    printf("unlocked %s ", hold_name);
    if (deadline) {
      char tb[64];
      struct tm tmv;
      localtime_r(&deadline, &tmv);
      strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S", &tmv);
      printf("until %s (holder pid %d)\n", tb, (int)pid);
    } else {
      printf("until bot-auth lock (holder pid %d)\n", (int)pid);
    }
    return 0;
  }
  (void)setsid();
  if (chdir("/") != 0) { /* keep going */ }
  int dn = open("/dev/null", O_RDWR);
  if (dn >= 0) {
    (void)dup2(dn, 0);
    (void)dup2(dn, 1);
    (void)dup2(dn, 2);
    if (dn > 2) close(dn);
  }
  struct sigaction sg;
  memset(&sg, 0, sizeof(sg));
  sg.sa_handler = on_hold_signal; /* no SA_RESTART: poll() returns EINTR */
  sigemptyset(&sg.sa_mask);
  (void)sigaction(SIGINT, &sg, NULL);
  (void)sigaction(SIGTERM, &sg, NULL);
  (void)sigaction(SIGHUP, &sg, NULL);
  signal(SIGPIPE, SIG_IGN);
  bool go_on = true;
  while (go_on && !hold_stop) {
    int ms = -1;
    if (deadline) {
      time_t now = time(NULL);
      if (now >= deadline) break;
      ms = (deadline - now) > 3600 ? 3600000 : (int)(deadline - now) * 1000;
    }
    struct pollfd pf = {ls, POLLIN, 0};
    int r = poll(&pf, 1, ms);
    if (r <= 0) continue; /* timeout or a signal: the loop checks both */
    int c = accept(ls, NULL, NULL);
    if (c < 0) continue;
    struct timeval tv = {2, 0};
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (peer_is_me(c)) go_on = hold_serve(c, deadline);
    close(c);
  }
  hold_wipe();
  close(ls);
  unlink(name);
  _exit(0);
}
#endif

static void harden(void) {
#ifdef _WIN32
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
  struct rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__) && defined(PR_SET_DUMPABLE)
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); /* no same-uid ptrace of the holder */
#endif
#endif
}

static int cmd_unlock(const char *keyfile, const char *expire, const char *passfile) {
  long secs = parse_expire(expire ? expire : "1h");
  if (secs == -2) die(1, "--expire: use e.g. 30m, 1h, 6h, 1d, a number of seconds, or never");
  if (secs == 0) die(1, "--expire 0 means ask every time: use no key holder at all");
  char name[PATH_MAX];
  unsigned char tb[32];
  if (!holder_name(keyfile, name, sizeof(name))) die(1, "cannot name the key holder");
  int tl = holder_call(name, 'T', NULL, 0, tb, sizeof(tb) - 1);
  if (tl > 0) {
    tb[tl] = '\0';
    printf("already unlocked (%s%s left)\n", (char *)tb, strcmp((char *)tb, "never") ? " s" : "");
    return 0;
  }
  static userkey_t k;
  lock_mem(&k, sizeof(k));
  char line[IRCKEY_LINE_MAX + 2];
  FILE *f = fopen(keyfile, "r");
  if (!f || !fgets(line, sizeof(line), f)) die(1, "cannot read the key file");
  fclose(f);
  if (!is_irckey(line)) {
    printf("%s has no passphrase: nothing to unlock (add one: keygen --passwd)\n", keyfile);
    return 0;
  }
  load_key_ex(keyfile, &k, false, passfile);
  snprintf(k.holder, sizeof(k.holder), "%s", name);
  hold_key = &k;
  hold_name = keyfile;
  return hold_run(secs > 0 ? time(NULL) + secs : 0);
}

static int cmd_lock(const char *keyfile) {
  char name[PATH_MAX];
  unsigned char b[4];
  if (!holder_name(keyfile, name, sizeof(name))) die(1, "cannot name the key holder");
  if (holder_call(name, 'Q', NULL, 0, b, sizeof(b)) < 0) {
    printf("locked (no key holder was running)\n");
    return 0;
  }
  printf("locked\n");
  return 0;
}

static int cmd_status(const char *keyfile) {
  char name[PATH_MAX];
  unsigned char tb[32];
  if (!holder_name(keyfile, name, sizeof(name))) die(1, "cannot name the key holder");
  int tl = holder_call(name, 'T', NULL, 0, tb, sizeof(tb) - 1);
  if (tl <= 0) {
    printf("locked\n");
    return EXIT_LOCKED;
  }
  tb[tl] = '\0';
  printf("unlocked %s\n", (char *)tb);
  return 0;
}

static void usage(void) {
  fprintf(stderr,
          "usage: bot-auth auth <keyfile> <botnick> <yournick>\n"
          "       bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply> [--pin <pinfile>]\n"
          "       bot-auth cmd  <keyfile> <botnick> <yournick> <botpubkey|@file> [--sealed <replykeyfile>]\n"
          "                     (command on stdin)\n"
          "       bot-auth reply <replykeyfile> <botnick> <yournick>   (~A2R lines on stdin)\n"
          "       bot-auth fp   <pubkey|file>\n"
          "       bot-auth unlock <keyfile> [--expire <30m|1h|6h|1d|secs|never>] [--passphrase-file <f>]\n"
          "       bot-auth lock   <keyfile>\n"
          "       bot-auth status <keyfile>\n"
          "keyfile is your <ts>_<name>.private.b64 (chmod 600). See utils/README.txt.\n");
  exit(1);
}

int main(int argc, char **argv) {
  harden();
  if (argc < 2) usage();
  const char *sub = argv[1];
  if (strcmp(sub, "auth") == 0 && argc == 5) return cmd_auth(argv[2], argv[3], argv[4]);
  if (strcmp(sub, "open") == 0 && (argc == 7 || argc == 9)) {
    const char *pin = NULL;
    if (argc == 9) {
      if (strcmp(argv[7], "--pin") != 0) usage();
      pin = argv[8];
    }
    return cmd_open(argv[2], argv[3], argv[4], argv[5], argv[6], pin);
  }
  if (strcmp(sub, "cmd") == 0 && argc == 6)
    return cmd_cmd(argv[2], argv[3], argv[4], argv[5], NULL);
  if (strcmp(sub, "cmd") == 0 && argc == 8 && strcmp(argv[6], "--sealed") == 0)
    return cmd_cmd(argv[2], argv[3], argv[4], argv[5], argv[7]);
  if (strcmp(sub, "reply") == 0 && argc == 5) return cmd_reply(argv[2], argv[3], argv[4]);
  if (strcmp(sub, "fp") == 0 && argc == 3) return cmd_fp(argv[2]);
  if (strcmp(sub, "unlock") == 0 && argc >= 3) {
    const char *exp = NULL, *pf = NULL;
    for (int i = 3; i < argc; i++) {
      if (strcmp(argv[i], "--expire") == 0 && i + 1 < argc && !exp) exp = argv[++i];
      else if (strcmp(argv[i], "--passphrase-file") == 0 && i + 1 < argc && !pf) pf = argv[++i];
      else usage();
    }
    return cmd_unlock(argv[2], exp, pf);
  }
  if (strcmp(sub, "lock") == 0 && argc == 3) return cmd_lock(argv[2]);
  if (strcmp(sub, "status") == 0 && argc == 3) return cmd_status(argv[2]);
  usage();
  return 1;
}
