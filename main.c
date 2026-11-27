#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "bot.h"
#include "cli_fmt.h"

void ssl_init_openssl(void) {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/* Process hardening: keep secrets out of anything that lands on disk.
 *
 * PR_SET_DUMPABLE(0) suppresses the core dump on a crash.  Without it a
 * crash hands the bot's identity private key and the config password to
 * /proc/sys/kernel/core_pattern -- on this host that pipes to
 * systemd-coredump, i.e. straight to disk.  It also blocks same-uid ptrace
 * attach, complementing kernel.yama.ptrace_scope.
 *
 * RLIMIT_CORE 0 covers the same ground and, unlike the dumpable flag
 * (which the kernel resets to 1 on execve), is inherited across the
 * updater's exec in utils.c.
 *
 * Neither defends against root.  See docs/admin_cmd_encryption.md.
 * Called before any config or key material is loaded. */
static void harden_process(void) {
  /* Private by default whatever the shell's umask (Ubuntu's is 002): the
   * setup wizard, pid, log and upgrade staging all inherit it. */
  umask(0077);
  struct rlimit rl = { 0, 0 };
  setrlimit(RLIMIT_CORE, &rl);
#ifdef PR_SET_DUMPABLE
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* Instance directory: .ircbot.cnf/.pass/.pid/.log/.upgrade all live beside
 * the binary, so the bot behaves the same whatever the caller's cwd -- cron
 * starts jobs in $HOME.  One binary per bot.  Our own path comes from
 * /proc/self/exe (argv[0] has no directory when launched through PATH);
 * fills `exe` with it and chdir()s to its directory.  That directory holds
 * the binary an upgrade replaces, its .prev and the upgrade script, so refuse
 * one another user owns and chmod go-w one group/other can write -- they could
 * swap any of them.  Mirrors instance_dir_enter() in irchub/hub_main.c. */
static bool instance_dir_enter(char *exe, size_t exe_len) {
  ssize_t n = readlink("/proc/self/exe", exe, exe_len - 1);
  if (n <= 0 || (size_t)n >= exe_len - 1) {
    fprintf(stderr, "Cannot resolve my own path (/proc/self/exe)\n");
    return false;
  }
  exe[n] = '\0';
  char dir[PATH_MAX];
  snprintf(dir, sizeof(dir), "%s", exe);
  char *slash = strrchr(dir, '/');
  if (!slash) {
    fprintf(stderr, "Cannot resolve my own directory from %s\n", exe);
    return false;
  }
  slash[slash == dir ? 1 : 0] = '\0';
  /* fd-based from here on: the directory inspected is the one fixed and
   * entered. */
  int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  struct stat st;
  if (dfd < 0 || fstat(dfd, &st) != 0) {
    if (dfd >= 0) close(dfd);
    fprintf(stderr, "Cannot stat my own directory %s\n", dir);
    return false;
  }
  if (st.st_uid != geteuid()) {
    close(dfd);
    fprintf(stderr, "Refusing to run from %s: it must be owned by this "
                    "user\n", dir);
    return false;
  }
  /* Group/other write (a 002 umask makes 0775 directories): we own it, so
   * close the hole rather than refuse -- refusing turned every upgrade on
   * such a host into a watchdog rollback and a fresh install into a dead
   * start.  Nothing is weakened: the directory was open before we ran. */
  if (st.st_mode & (S_IWGRP | S_IWOTH)) {
    mode_t m = st.st_mode & 07777 & ~(mode_t)(S_IWGRP | S_IWOTH);
    if (fchmod(dfd, m) != 0) {
      fprintf(stderr, "Refusing to run from %s: group/other can write it "
                      "and chmod go-w failed (%s)\n", dir, strerror(errno));
      close(dfd);
      return false;
    }
    fprintf(stderr, "Removed group/other write from %s (now %04o)\n", dir,
            (unsigned)m);
  }
  if (fchdir(dfd) != 0) {
    close(dfd);
    fprintf(stderr, "Cannot change to my own directory %s\n", dir);
    return false;
  }
  close(dfd);
  return true;
}

static void state_init(bot_state_t *state) {
  memset(state, 0, sizeof(bot_state_t));
  /* Lock the whole state into RAM so no part of it can reach swap or a
   * hibernation image.  bot_state_t is ~301 KB against a 4 MB RLIMIT_MEMLOCK,
   * so locking wholesale is cheaper than tracking individual fields and it
   * covers hub_key[] (base64 of the combined private key), hub_session_key[],
   * startup_password, and anything secret added later.  Best-effort: a failure
   * here is not fatal. */
  if (mlock(state, sizeof(bot_state_t)) != 0)
    fprintf(stderr, "Warning: mlock(state) failed (%s) - "
                    "secrets may reach swap.\n", strerror(errno));
  state->status = S_NONE;
  state->log_type = DEFAULT_LOG_LEVEL;
  state->log_max_size = BOT_LOG_FILE_SIZE;
  state->bot_start_time = time(NULL);
  state->last_pong_time = time(NULL);
  state->nick_release_time = time(NULL) - NICK_TAKE_TIME;
  state->actual_hostname_ts = 0;
  state->current_nick_ts = time(NULL);
  state->server_fd = -1;
  state->server_count = 0;
  state->user_record_count = 0;
  state->mask_record_count = 0;
  state->trusted_bot_count = 0;
  state->config_dirty = false;
  state->last_config_write = 0;
  sendq_init(state);
  isupport_reset(state);
  hub_client_init(state);
  dcc_init(state);
  srand((unsigned)time(NULL));
}

static void state_destroy(bot_state_t *state) {
  free(state->chan_state_sent);
  state->chan_state_sent = NULL;
  for (int i = 0; i < state->server_count; i++)
    free(state->server_list[i]);
  for (int i = 0; i < state->local_server_count; i++)
    free(state->local_servers[i]);
  /* hubs[] is an embedded array (no heap), but wipe the pinned key bytes. */
  for (int i = 0; i < state->hub_count; i++)
    OPENSSL_cleanse(state->hubs[i].ed_pub, sizeof(state->hubs[i].ed_pub));
  channel_list_destroy(state);
  sendq_clear(state);
  chancfg_free(state);
  /* The base64 copy of the identity key and the live session key die with
   * the raw key (the whole state is mlock'd in state_init; this is the wipe). */
  OPENSSL_cleanse(state->hub_key,         sizeof(state->hub_key));
  OPENSSL_cleanse(state->hub_session_key, sizeof(state->hub_session_key));
  OPENSSL_cleanse(state->hub_key_raw,     sizeof(state->hub_key_raw));
  munlock(state->hub_key_raw,             sizeof(state->hub_key_raw));
  OPENSSL_cleanse(state->startup_password, MAX_PASS);
  munlock(state->startup_password,         MAX_PASS);
}

static void flush_stdin_if_needed(const char *buffer, size_t len) {
  if (strlen(buffer) == len - 1 && strchr(buffer, '\n') == NULL) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
      ;
  }
}

static void get_password(const char *prompt, char *buffer, size_t len) {
  struct termios oldt, newt;
  printf("%s: ", prompt);
  fflush(stdout);
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(tcflag_t)ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  if (fgets(buffer, (int)len, stdin) == NULL) {
    buffer[0] = '\0';
  } else {
    flush_stdin_if_needed(buffer, len);
    buffer[strcspn(buffer, "\r\n")] = 0;
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  printf("\n");
}

void daemonize(void) {
  pid_t pid;

  pid = fork();
  if (pid < 0) { perror("fork"); exit(1); }
  if (pid > 0) exit(0);

  if (setsid() < 0) { perror("setsid"); exit(1); }

  pid = fork();
  if (pid < 0) { perror("fork"); exit(1); }
  if (pid > 0) exit(0);

  umask(0077);

  int devnull = open("/dev/null", O_RDWR);
  if (devnull < 0) exit(1);
  dup2(devnull, STDIN_FILENO);
  dup2(devnull, STDOUT_FILENO);
  dup2(devnull, STDERR_FILENO);
  if (devnull > STDERR_FILENO) close(devnull);
}

static void passfile_build_context(char *buf, size_t len) {
  struct stat home_st;
  struct utsname uts;
  struct passwd *pw = getpwuid(getuid());

  memset(&home_st, 0, sizeof(home_st));
  memset(&uts, 0, sizeof(uts));
  if (pw && pw->pw_dir)
    stat(pw->pw_dir, &home_st);
  uname(&uts);

  snprintf(buf, len, "%ju:%ju:%u:%u:%.64s",
           (uintmax_t)home_st.st_ino,
           (uintmax_t)home_st.st_dev,
           (unsigned int)getuid(),
           (unsigned int)getgid(),
           uts.machine);
}

static bool passfile_derive_key(const char *ctx, const unsigned char *salt,
                                int iterations, unsigned char *key) {
  return PKCS5_PBKDF2_HMAC(ctx, (int)strlen(ctx), salt, SALT_SIZE,
                            iterations, EVP_sha256(), 32, key) == 1;
}

static bool passfile_create(const char *path, const char *password) {
  unsigned char salt[SALT_SIZE];
  unsigned char key[32];
  unsigned char tag[GCM_TAG_LEN];
  char ctx[256];
  bool ok = false;

  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    fprintf(stderr, "RNG failure.\n");
    goto done;
  }

  passfile_build_context(ctx, sizeof(ctx));
  if (!passfile_derive_key(ctx, salt, PBKDF2_ITERATIONS, key)) {
    fprintf(stderr, "Key derivation failed.\n");
    goto done;
  }

  int pass_len = (int)strlen(password);
  unsigned char *enc_buf = malloc((size_t)(GCM_IV_LEN + pass_len));
  if (!enc_buf) goto done;

  int enc_len = crypto_aes_gcm_encrypt((const unsigned char *)password,
                                       pass_len, key, enc_buf, tag);
  if (enc_len <= 0) {
    fprintf(stderr, "Encryption failed.\n");
    free(enc_buf);
    goto done;
  }

  /* Written beside it and renamed over it, so a rewrite (-p) never leaves
   * a half-written pass file. */
  char tmp[PATH_MAX];
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
    free(enc_buf);
    goto done;
  }
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) { perror("open"); free(enc_buf); goto done; }
  if (fchmod(fd, 0600) != 0) { perror("fchmod"); close(fd); remove(tmp); free(enc_buf); goto done; }

  ok = (write(fd, salt,    SALT_SIZE)   == SALT_SIZE &&
        write(fd, enc_buf, (size_t)enc_len) == enc_len &&
        write(fd, tag,     GCM_TAG_LEN) == GCM_TAG_LEN);

  if (!ok) perror("write " PASS_FILE);
  if (close(fd) != 0) ok = false;
  if (ok && rename(tmp, path) != 0) { perror("rename " PASS_FILE); ok = false; }
  if (!ok) remove(tmp);
  free(enc_buf);

done:
  memset(key, 0, sizeof(key));
  memset(ctx, 0, sizeof(ctx));
  return ok;
}

static bool passfile_load(const char *path, char *out_pass, size_t out_len) {
  struct stat st;
  bool ok = false;

  if (stat(path, &st) != 0) return false;

  if (st.st_uid != getuid()) {
    fprintf(stderr, "[WARN] %s: wrong owner, ignoring.\n", path);
    return false;
  }
  if ((st.st_mode & 0777) != 0600) {
    fprintf(stderr, "[WARN] %s: must be 0600, ignoring.\n", path);
    return false;
  }

  int min_size = SALT_SIZE + GCM_IV_LEN + 1 + GCM_TAG_LEN;
  if (st.st_size < min_size) return false;

  int fd = open(path, O_RDONLY);
  if (fd < 0) return false;

  size_t total = (size_t)st.st_size;
  unsigned char *buf = malloc(total);
  if (!buf) { close(fd); return false; }

  if (read(fd, buf, total) != (ssize_t)total) {
    close(fd); free(buf); return false;
  }
  close(fd);

  unsigned char *salt    = buf;
  unsigned char *enc_blk = buf + SALT_SIZE;
  int enc_len            = (int)(total - SALT_SIZE - GCM_TAG_LEN);
  unsigned char *tag     = buf + SALT_SIZE + enc_len;

  unsigned char key[32];
  char ctx[256];
  passfile_build_context(ctx, sizeof(ctx));

  mlock(out_pass, out_len);
  unsigned char *plain = malloc((size_t)enc_len);
  if (!plain) goto done;
  mlock(plain, (size_t)enc_len);

  int dec_len = -1;
  if (passfile_derive_key(ctx, salt, PBKDF2_ITERATIONS, key))
    dec_len = crypto_aes_gcm_decrypt(enc_blk, enc_len, key, plain, tag);
  if (dec_len > 0 && (size_t)dec_len < out_len) {
    plain[dec_len] = 0;
    memcpy(out_pass, plain, (size_t)dec_len + 1);
    ok = true;
  } else {
    fprintf(stderr, "[WARN] %s: decryption failed (wrong machine, tampered, or "
            "written before 2.5.0).\n", path);
  }

  memset(plain, 0, (size_t)enc_len);
  munlock(plain, (size_t)enc_len);
  free(plain);

done:
  memset(key, 0, sizeof(key));
  memset(ctx, 0, sizeof(ctx));
  munlock(out_pass, out_len);
  free(buf);
  return ok;
}

/* Read a user's public key for the wizard: the pasted 88-char key, or a
 * path to their .public.b64.  Shows the fingerprint and asks to confirm. */
static void wizard_read_pubkey(const char *who, char out[COMBINED_KEY_B64 + 1]) {
  for (;;) {
    char in[PATH_MAX];
    unsigned char raw[HUB_KEY_RAW_LEN];
    out[0] = '\0';
    cli_ask("public key", in, sizeof(in));
    if (feof(stdin)) {
      cli_err("no public key given: setup stopped");
      exit(1);
    }
    if (in[0] == '\0') {
      cli_err("a public key is required: make one with 'utils/keygen %s' and give its "
              ".public.b64", who);
      continue;
    }
    /* Private and public key files have the same shape; refuse a keygen
     * private file by name before it gets published in the a| record. */
    if (strstr(in, ".private.")) {
      cli_err("that is a PRIVATE key file: it stays with the admin; give the .public.b64");
      continue;
    }
    if (crypto_pubkey_b64_decode(in, raw)) {
      /* decode succeeded => exactly COMBINED_KEY_B64 chars */
      memcpy(out, in, COMBINED_KEY_B64);
      out[COMBINED_KEY_B64] = '\0';
    } else {
      FILE *f = fopen(in, "r");
      char line[256] = {0};
      if (f) {
        if (!fgets(line, sizeof(line), f)) line[0] = '\0';
        fclose(f);
        line[strcspn(line, " \t\r\n")] = '\0';
      }
      if (!line[0] || !crypto_pubkey_b64_decode(line, raw)) {
        cli_err("not an 88-char public key%s (the .public.b64, never the .private.b64)",
                f ? " in that file" : "");
        continue;
      }
      memcpy(out, line, COMBINED_KEY_B64);
      out[COMBINED_KEY_B64] = '\0';
    }
    char fp[KEY_FP_LEN + 1];
    crypto_key_fingerprint(raw, fp);
    cli_kv("fingerprint", "%s", fp);
    if (cli_ask_yes("use this key?", true)) return;
  }
}

/* A hub's pinned key for a summary line: the fingerprint of an 88-char
 * combined key, or a 44-char Ed25519 key shortened. */
/* -setup: can the bot dial out from vhost?  It must be an IPv4 or IPv6
 * literal (what irc_client.c binds) of this host: a throwaway socket is
 * bound to it on port 0 and closed.  why gets the reason. */
static bool wizard_test_vhost(const char *vhost, char *why, size_t cap) {
  struct sockaddr_storage ss;
  socklen_t sl;
  memset(&ss, 0, sizeof(ss));
  struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;
  if (inet_pton(AF_INET, vhost, &v4->sin_addr) == 1) {
    v4->sin_family = AF_INET;
    sl = sizeof(*v4);
  } else if (inet_pton(AF_INET6, vhost, &v6->sin6_addr) == 1) {
    v6->sin6_family = AF_INET6;
    sl = sizeof(*v6);
  } else {
    snprintf(why, cap, "not an IP address (a hostname is not accepted)");
    return false;
  }
  int fd = socket(ss.ss_family, SOCK_STREAM, 0);
  if (fd < 0) {
    snprintf(why, cap, "%s", strerror(errno));
    return false;
  }
  bool ok = bind(fd, (struct sockaddr *)&ss, sl) == 0;
  int e = errno;
  close(fd);
  if (ok) return true;
  if (e == EADDRNOTAVAIL) snprintf(why, cap, "not an address of this host");
  else snprintf(why, cap, "%s", strerror(e));
  return false;
}

static const char *wizard_hub_key_label(const char *in, char *out, size_t cap) {
  unsigned char raw[HUB_KEY_RAW_LEN];
  if (crypto_pubkey_b64_decode(in, raw)) {
    char fp[KEY_FP_LEN + 1];
    crypto_key_fingerprint(raw, fp);
    snprintf(out, cap, "key %s", fp);
    secure_wipe(raw, sizeof(raw));
  } else {
    char sh[64];
    snprintf(out, cap, "key %s", cli_short(in, sh, sizeof(sh)));
  }
  return out;
}

static void run_config_wizard(void) {
  bot_state_t state;
  char config_pass[MAX_PASS];
  char server_buf[MAX_BUFFER];
  char chan_buf[MAX_CHAN];
  char admin_name[64];
  char admin_pub[COMBINED_KEY_B64 + 1];
  char pub_b64_keep[COMBINED_KEY_B64 + 1];
  char id_fp[KEY_FP_LEN + 1];
#define WIZARD_MAX_MASKS 20
  char admin_masks[WIZARD_MAX_MASKS][MAX_MASK_LEN];
  /* what the summary shows for each hub: its pasted key, kept as typed */
  char hub_keys[MAX_HUBS][96];
  int  admin_mask_count = 0;
  bool hub_managed = false;
  memset(admin_name,  0, sizeof(admin_name));
  memset(admin_pub,   0, sizeof(admin_pub));
  memset(admin_masks, 0, sizeof(admin_masks));

  cli_header("ircbot", BOT_VERSION, "setup");
  cli_note("No %s here yet: these steps write one, encrypted with a config password.",
           CONFIG_FILE);

  do {
    state_init(&state);
    memset(config_pass, 0, MAX_PASS);
    memset(server_buf, 0, MAX_BUFFER);
    memset(chan_buf, 0, MAX_CHAN);
    memset(hub_keys, 0, sizeof(hub_keys));
    pub_b64_keep[0] = '\0';
    id_fp[0] = '\0';

    /* Reset every mode-dependent field here rather than at its prompt: the
     * prompts now live in mutually exclusive branches, so a wizard restart that
     * switches from standalone to hub-managed would otherwise carry the first
     * pass's admin name/key/masks into the committed config. */
    hub_managed = false;
    admin_mask_count = 0;
    memset(admin_name,  0, sizeof(admin_name));
    memset(admin_pub,   0, sizeof(admin_pub));
    memset(admin_masks, 0, sizeof(admin_masks));
    int step = 0;

    cli_step(++step, "Config password");
    for (;;) {
      char confirm[MAX_PASS];
      cli_ask_secret("password", config_pass, MAX_PASS);
      cli_ask_secret("confirm", confirm, sizeof(confirm));
      bool same = config_pass[0] && strcmp(config_pass, confirm) == 0;
      OPENSSL_cleanse(confirm, sizeof(confirm));
      if (same) {
        cli_ok("the passwords match");
        break;
      }
      cli_err("the passwords do not match, or are empty: again");
      OPENSSL_cleanse(config_pass, MAX_PASS);
    }

    /* Bot identity is generated locally up front: the summary shows the
     * exact 'bot add' line for the hub console.  The private key never
     * leaves this machine. */
    cli_step(++step, "Identity (generated here, Curve25519)");
    {
      unsigned char priv64[HUB_KEY_RAW_LEN], pub64[HUB_KEY_RAW_LEN];
      if (!crypto_generate_combined_keypair(priv64, pub64)) {
        cli_err("could not generate the bot's keypair");
        return;
      }
      /* UUID v4 */
      unsigned char rnd[16];
      if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        cli_err("RAND_bytes failed");
        secure_wipe(priv64, HUB_KEY_RAW_LEN);
        return;
      }
      rnd[6] = (unsigned char)((rnd[6] & 0x0f) | 0x40);
      rnd[8] = (unsigned char)((rnd[8] & 0x3f) | 0x80);
      snprintf(state.bot_uuid, sizeof(state.bot_uuid),
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
               "%02x%02x%02x%02x%02x%02x",
               rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
               rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);
      /* Store priv into the encrypted-config slot (k|<base64>) and the
       * mlock'd raw cache. */
      char *priv_b64 = base64_encode(priv64, HUB_KEY_RAW_LEN);
      char *pub_b64  = base64_encode(pub64,  HUB_KEY_RAW_LEN);
      if (!priv_b64 || !pub_b64) {
        cli_err("base64 encode failed");
        if (priv_b64) { secure_wipe(priv_b64, strlen(priv_b64)); free(priv_b64); }
        if (pub_b64)  free(pub_b64);
        secure_wipe(priv64, HUB_KEY_RAW_LEN);
        return;
      }
      snprintf(state.hub_key, sizeof(state.hub_key), "%s", priv_b64);
      memcpy(state.hub_key_raw, priv64, HUB_KEY_RAW_LEN);
      mlock(state.hub_key_raw, HUB_KEY_RAW_LEN);
      secure_wipe(priv64, HUB_KEY_RAW_LEN);
      secure_wipe(priv_b64, strlen(priv_b64));
      free(priv_b64);

      crypto_key_fingerprint(pub64, id_fp);
      snprintf(pub_b64_keep, sizeof(pub_b64_keep), "%s", pub_b64);
      cli_kv("uuid", "%s", state.bot_uuid);
      cli_kv("public key", "%s", pub_b64);
      cli_kv("fingerprint", "%s", id_fp);
      cli_note("The summary at the end has the 'bot add' line for the hub console.");
      free(pub_b64);
    }

    cli_step(++step, "On IRC");
    while (true) {
      cli_ask("nick", state.target_nick, MAX_NICK);
      if (is_rfc_nick(state.target_nick)) {
        snprintf(state.current_nick, MAX_NICK, "%s", state.target_nick);
        break;
      }
      if (strchr(state.target_nick, '|'))
        cli_err("a nick cannot hold '|' (it delimits the records)");
      else if (!is_valid_bot_nick(state.target_nick))
        cli_err("a nick is 1-%d characters", MAX_NICK - 1);
      else
        cli_err("not an IRC nick: start with a letter or one of []\\`_^{}, then letters, "
                "digits, those or '-'");
    }
    cli_ask("ident", state.user, sizeof(state.user));
    cli_ask("real name", state.gecos, sizeof(state.gecos));
    /* Optional: most bots dial out from the host's default address. */
    cli_note("A vhost is optional: a local IP address the bot dials IRC from "
             "(for a host with several).");
    state.vhost[0] = '\0';
    if (cli_ask_yes("do you have a vhost?", false)) {
      for (;;) {
        char why[128];
        cli_ask("vhost ip (empty = none)", state.vhost, sizeof(state.vhost));
        if (!state.vhost[0] || feof(stdin)) break;
        if (wizard_test_vhost(state.vhost, why, sizeof(why))) {
          cli_ok("%s can be bound", state.vhost);
          break;
        }
        cli_err("cannot use %s: %s", state.vhost, why);
        state.vhost[0] = '\0';
      }
    }
    if (!state.vhost[0]) cli_note("no vhost: the system's default address");

    /* Management mode decides the rest of the wizard.  A hub-managed bot owns
     * none of the records the hub is authoritative for, so prompting for them
     * only produces local state the first sync discards — or, under opt 'h'
     * (OPT_HUB_ONLY_MUTATIONS), state the hub rejects outright and the bot then
     * re-pushes forever with no way to notice.  Ask first, collect only what
     * this bot actually owns. */
    cli_step(++step, "Management");
    cli_note("hub-managed: admins, usermasks, channels and IRC servers live on the hub "
             "and are managed on its console; this bot needs only the hubs' addresses "
             "and keys.");
    cli_note("standalone: this bot keeps its own IRC server, admin and channel.");
    hub_managed = cli_ask_yes("hub-managed?", true);

    if (hub_managed) {
      cli_step(++step, "Hubs");
      cli_note("Each hub's address and public key: './irchub -id' on its host prints "
               "both (the '+hub' line), and so does 'hub show' on its console.");

      while (state.hub_count < MAX_HUBS) {
        char hub_addr[256];
        char hub_pub_input[256];
        bool addr_valid = false;
        bool hpub_valid = false;

        printf("\n");
        while (!addr_valid) {
          char label[24];
          snprintf(label, sizeof(label), "hub %d", state.hub_count + 1);
          cli_ask(label, hub_addr, sizeof(hub_addr));
          char *colon = strrchr(hub_addr, ':');
          if (colon && colon != hub_addr && strlen(colon + 1) > 0) {
            int port = atoi(colon + 1);
            if (port > 0 && port < 65536) addr_valid = true;
          }
          if (!addr_valid) cli_err("give host:port (e.g. 127.0.0.1:6000)");
        }

        /* Reject duplicate addresses. */
        bool dup = false;
        for (int i = 0; i < state.hub_count; i++)
          if (strcmp(state.hubs[i].addr, hub_addr) == 0) { dup = true; break; }
        if (dup) {
          cli_err("%s is already in the list: skipped", hub_addr);
        } else {
          /* Hub public key: the 88-char combined key every hub tool prints. */
          unsigned char hub_pub[32];
          while (!hpub_valid) {
            cli_ask("public key", hub_pub_input, sizeof(hub_pub_input));
            size_t hp_len = strlen(hub_pub_input);
            while (hp_len > 0 && (hub_pub_input[hp_len-1] == ' ' ||
                                  hub_pub_input[hp_len-1] == '\r' ||
                                  hub_pub_input[hp_len-1] == '\n' ||
                                  hub_pub_input[hp_len-1] == '\t')) {
              hub_pub_input[--hp_len] = '\0';
            }
            int dec_len = 0;
            unsigned char *dec = base64_decode(hub_pub_input, &dec_len);
            if (!dec || dec_len != HUB_KEY_RAW_LEN) {
              cli_err("expected the hub's 88-char public key (./irchub -id or hub show)");
              if (dec) free(dec);
              continue;
            }
            /* First 32 bytes are the Ed25519 portion — what the bot verifies
             * hub challenges against. */
            memcpy(hub_pub, dec, 32);
            secure_wipe(dec, (size_t)dec_len);
            free(dec);
            hpub_valid = true;
          }

          hub_entry_t *he = &state.hubs[state.hub_count];
          memset(he, 0, sizeof(*he));
          snprintf(he->addr, sizeof(he->addr), "%s", hub_addr);
          memcpy(he->ed_pub, hub_pub, 32);
          he->ed_pub_set = true;
          secure_wipe(hub_pub, sizeof(hub_pub));
          size_t hk_len = strnlen(hub_pub_input, sizeof(hub_keys[0]) - 1); /* validated 88-char key */
          memcpy(hub_keys[state.hub_count], hub_pub_input, hk_len);
          hub_keys[state.hub_count][hk_len] = '\0';
          state.hub_count++;
          cli_ok("hub %d: %s", state.hub_count, hub_addr);
        }

        if (state.hub_count >= MAX_HUBS) {
          cli_note("That is the most hubs a bot keeps (%d).", MAX_HUBS);
          break;
        }
        if (!cli_ask_yes("another hub?", false)) break;
      }
      if (state.hub_count == 0) {
        /* Defensive: the loop above always adds on its first pass, so this is
         * unreachable today.  Fail closed rather than write a hub-managed
         * config with nothing to connect to. */
        cli_err("a hub-managed bot needs at least one hub: starting over");
        continue;
      }
    } else {
      cli_step(++step, "IRC server");
      while (true) {
        cli_ask("server", server_buf, MAX_BUFFER);
        char wh[POOL_HOST_MAX + 1];
        int wp = 0;
        if (strchr(server_buf, '.') &&
            pool_hostport_parse(server_buf, wh, sizeof(wh), &wp))
          break;
        cli_err("give host or host:port (e.g. irc.efnet.org:6697)");
      }

      cli_step(++step, "First admin");
      while (true) {
        cli_ask("name", admin_name, sizeof(admin_name));
        if (strlen(admin_name) > 0 && !strchr(admin_name,' ') && !strchr(admin_name,'|'))
          break;
        cli_err("a name with no spaces or '|' (e.g. admin)");
      }
      cli_note("The admin signs in with a Curve25519 key, not a password: on the admin's "
               "own machine run 'utils/keygen %s' (or see 'help +admin' for an openssl "
               "recipe) and give its .public.b64 here.  The .private.b64 stays with the "
               "admin (chmod 600) for their IRC script.", admin_name);
      wizard_read_pubkey(admin_name, admin_pub);
      cli_note("Usermasks the admin is known by (e.g. nick!*@*.example.com); an empty "
               "line ends the list, at least one.");
      while (admin_mask_count < WIZARD_MAX_MASKS) {
        char tmp_mask[MAX_MASK_LEN] = {0};
        char label[24];
        snprintf(label, sizeof(label), "usermask %d", admin_mask_count + 1);
        cli_ask(label, tmp_mask, sizeof(tmp_mask));
        if (feof(stdin)) break;
        if (tmp_mask[0] == '\0') {
          if (admin_mask_count == 0) { cli_err("at least one usermask"); continue; }
          break;
        }
        if (!strchr(tmp_mask, '!') || !strchr(tmp_mask, '@')) {
          cli_err("a usermask holds '!' and '@' (nick!user@host)");
          continue;
        }
        snprintf(admin_masks[admin_mask_count], MAX_MASK_LEN, "%s", tmp_mask);
        admin_mask_count++;
      }

      cli_step(++step, "First channel");
      while (true) {
        cli_ask("channel", chan_buf, MAX_CHAN);
        if (strlen(chan_buf) == 0) {
          cli_note("none: add channels later with 'join' from IRC");
          break;
        }
        if (chan_buf[0] == '#' && strlen(chan_buf) > 1)
          break;
        cli_err("a channel starts with '#' (or leave it empty)");
      }
    }

    /* The summary: every answer, and what to paste on the other side. */
    cli_summary("Summary");
    if (hub_managed)
      cli_skv("mode", "hub-managed %s %d hub%s", cli_g(CLI_G_DOT), state.hub_count,
              state.hub_count == 1 ? "" : "s");
    else
      cli_skv("mode", "standalone");
    cli_skv("nick", "%s", state.target_nick);
    cli_skv("ident", "%s", state.user[0] ? state.user : "(the nick)");
    cli_skv("real name", "%s", state.gecos[0] ? state.gecos : "(none)");
    cli_skv("vhost", "%s", state.vhost[0] ? state.vhost : "(none)");
    if (hub_managed) {
      for (int i = 0; i < state.hub_count; i++) {
        char kl[96];
        cli_skv(i == 0 ? "hubs" : "", "%s  %s", state.hubs[i].addr,
                wizard_hub_key_label(hub_keys[i], kl, sizeof(kl)));
      }
      cli_skv("irc servers", "from the hub's pool");
    } else {
      cli_skv("irc server", "%s", server_buf);
      unsigned char raw[HUB_KEY_RAW_LEN];
      char fp[KEY_FP_LEN + 1] = "";
      if (crypto_pubkey_b64_decode(admin_pub, raw)) crypto_key_fingerprint(raw, fp);
      cli_skv("admin", "%s %s key %s", admin_name, cli_g(CLI_G_DOT), fp[0] ? fp : "?");
      for (int i = 0; i < admin_mask_count; i++)
        cli_skv(i == 0 ? "usermasks" : "", "%s", admin_masks[i]);
      cli_skv("channel", "%s", chan_buf[0] ? chan_buf : "(none)");
    }
    cli_skv("uuid", "%s", state.bot_uuid);
    cli_skv("key", "%s", id_fp);
    if (hub_managed) {
      cli_skv("on the hub", "paste this on ONE hub's console:");
      printf("\n   bot add %s %s %s\n\n", state.target_nick, state.bot_uuid, pub_b64_keep);
      cli_note("Once is enough: every linked hub learns the bot through the mesh.");
    } else {
      cli_skv("other bots", "trust this one with:");
      printf("\n   +bot %s!%s@<host> %s %s\n\n", state.target_nick,
             state.user[0] ? state.user : state.target_nick, state.bot_uuid, pub_b64_keep);
    }
    cli_rule();

    if (!cli_ask_yes("write " CONFIG_FILE "?", true)) {
      cli_note("Starting over.");
      for (int i = 0; i < state.hub_count; i++)
        OPENSSL_cleanse(state.hubs[i].ed_pub, sizeof(state.hubs[i].ed_pub));
      state.hub_count = 0;
    } else {
      break;
    }
  } while (true);

  /* Commit — create admin user_record + all collected mask_records.  Skipped
   * entirely for a hub-managed bot: the hub is authoritative for a|/m| records
   * and replaces the bot's set wholesale on the first sync
   * (hub_client_process_config_data), so anything written here is dead on
   * arrival.  The guard is load-bearing, not cosmetic — admin_name/admin_pub
   * are never populated in hub-managed mode, so running this unguarded would
   * persist an admin record with an empty name and no key. */
  if (!hub_managed) {
    unsigned char rnd[16];
    RAND_bytes(rnd, sizeof(rnd));
    rnd[6]=(unsigned char)((rnd[6]&0x0f)|0x40); rnd[8]=(unsigned char)((rnd[8]&0x3f)|0x80);
    char new_uuid[37];
    snprintf(new_uuid, sizeof(new_uuid),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
             rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);
    time_t now = time(NULL);
    user_record_t *u = &state.user_records[state.user_record_count++];
    memset(u, 0, sizeof(*u));
    snprintf(u->uuid,     sizeof(u->uuid),     "%s", new_uuid);
    snprintf(u->name,       sizeof(u->name),       "%s", admin_name);
    snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", admin_pub);
    u->has_pubkey = (admin_pub[0] != '\0');
    u->type = 'a'; u->is_active = true; u->timestamp = now;
    for (int mi = 0; mi < admin_mask_count && state.mask_record_count < MAX_USER_MASKS; mi++) {
      mask_record_t *m = &state.mask_records[state.mask_record_count++];
      memset(m, 0, sizeof(*m));
      snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
      snprintf(m->mask, sizeof(m->mask), "%.255s", admin_masks[mi]);
      m->is_active = true; m->timestamp = now;
    }
  }
  /* Wipe unconditionally — the buffers exist in both modes even though only the
   * standalone branch fills them. */
  secure_wipe(admin_masks, sizeof(admin_masks));
  secure_wipe(hub_keys, sizeof(hub_keys));
#undef WIZARD_MAX_MASKS
  /* Standalone: its one local server.  Hub-managed: none -- the hub's pool
   * arrives with the first sync (server pool plan §5.5a). */
  if (!hub_managed && server_buf[0]) {
    char *d = strdup(server_buf);
    if (d) state.local_servers[state.local_server_count++] = d;
  }

  if (strlen(chan_buf) > 0) {
    chan_t *c = channel_add(&state, chan_buf);
    if (c) {
      c->is_managed = true; // Active by default
      c->timestamp = time(NULL);
      c->status = C_OUT; // Will join on main loop start
    }
  }

  config_write(&state, config_pass);
  OPENSSL_cleanse(config_pass, MAX_PASS);
  printf("\n");
  cli_ok("wrote %s", CONFIG_FILE);
  cli_kv("next", "./ircbot -p, then ./ircbot");
  cli_note("-p writes a machine-bound password file, so the bot starts without typing "
           "the password; ./ircbot alone asks for it.");
  if (hub_managed)
    cli_note("The bot joins IRC once its first hub sync brings the server pool: if the "
             "hub has no servers yet, add one on its console ('server add <host[:port]>').");
  printf("\n");

  /* Release the wizard's local state: frees the local_servers[] entry (the
   * strdup at the server_buf line) and the channel list, and cleanses key
   * material. */
  state_destroy(&state);
  config_key_forget();
}

static int run_selftest(void) {
  /* The swap happens in this directory: one another user owns is refused at
   * start (a group/other-writable one we own is tightened there). */
  struct stat dst;
  if (stat(".", &dst) != 0 || dst.st_uid != geteuid()) {
    printf("selftest: FAIL this directory is not owned by this user\n");
    return 1;
  }
  if (access(CONFIG_FILE, R_OK) != 0) {
    printf("selftest: FAIL no readable %s\n", CONFIG_FILE);
    return 1;
  }
  char pw[MAX_PASS];
  memset(pw, 0, sizeof(pw));
  if (!passfile_load(PASS_FILE, pw, sizeof(pw))) {
    /* 2.5.1 reads only the 600k key; a pass file 2.5.0 never got to rewrite
     * (no ordinary start, or its deferred rewrite failed) is refused here so
     * the upgrade reports it instead of leaving a bot that cannot start. */
    printf("selftest: FAIL cannot read %s (written before 2.5.0? restart once "
           "on 2.5.0, or rewrite it with -p)\n", PASS_FILE);
    return 1;
  }
  bot_state_t *st = calloc(1, sizeof(*st));
  if (!st) {
    OPENSSL_cleanse(pw, sizeof(pw));
    printf("selftest: FAIL out of memory\n");
    return 1;
  }
  state_init(st);
  g_config_readonly = true;
  bool ok = config_load(st, pw, CONFIG_FILE);
  OPENSSL_cleanse(pw, sizeof(pw));
  state_destroy(st);
  OPENSSL_cleanse(st, sizeof(*st));
  free(st);
  if (!ok) {
    printf("selftest: FAIL cannot load %s\n", CONFIG_FILE);
    return 1;
  }
  printf("selftest: OK ircbot %s %s\n", BOT_VERSION, updater_host_variant());
  return 0;
}

/* -id: print this bot's uuid, public key and fingerprint — what the hub
 * console's `bot add` (or a standalone peer's +bot) needs — from the config,
 * and exit.  Read-only: no daemon, no PID lock, no config rewrite. */
static int run_identity(char *password) {
  bot_state_t *st = calloc(1, sizeof(*st));
  if (!st) {
    OPENSSL_cleanse(password, MAX_PASS);
    fprintf(stderr, "Out of memory.\n");
    return 1;
  }
  state_init(st);
  g_config_readonly = true;
  bool ok = config_load(st, password, CONFIG_FILE);
  OPENSSL_cleanse(password, MAX_PASS);
  int rc = 1;
  if (!ok) {
    fprintf(stderr, "Cannot load %s (wrong password?).\n", CONFIG_FILE);
  } else if (!st->self_pub_set || !st->bot_uuid[0]) {
    fprintf(stderr, "%s has no identity key or uuid; re-run -setup.\n",
            CONFIG_FILE);
  } else {
    char *pub_b64 = base64_encode(st->self_pub, HUB_KEY_RAW_LEN);
    char fp[KEY_FP_LEN + 1];
    crypto_key_fingerprint(st->self_pub, fp);
    if (pub_b64) {
      cli_header("ircbot", BOT_VERSION, "identity");
      printf("\n");
      cli_skv("nick", "%s", st->target_nick);
      cli_skv("uuid", "%s", st->bot_uuid);
      cli_skv("public key", "%s", pub_b64);
      cli_skv("fingerprint", "%s", fp);
      cli_skv("on the hub", "paste this on ONE hub's console:");
      printf("\n   bot add %s %s %s\n\n", st->target_nick, st->bot_uuid, pub_b64);
      cli_note("Once is enough: every linked hub learns the bot through the mesh.");
      cli_rule();
      free(pub_b64);
      rc = 0;
    }
  }
  state_destroy(st);
  OPENSSL_cleanse(st, sizeof(*st));
  free(st);
  return rc;
}

int main(int argc, char *argv[]) {
  harden_process();
#ifdef HAVE_CURL
  curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

  bool do_setup = false;
  bool do_passfile = false;
  bool do_identity = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-setup") == 0) do_setup = true;
    if (strcmp(argv[i], "-p")     == 0) do_passfile = true;
    if (strcmp(argv[i], "-id")    == 0) do_identity = true;
    /* -checkupdate [variant]: verify the release channel and exit; needs no
     * config, no password and no PID lock. */
    if (strcmp(argv[i], "-checkupdate") == 0)
      return updater_check_cli(i + 1 < argc ? argv[i + 1] : NULL);
    /* -selftest: could this binary run here, on this config?  No daemon, no
     * PID lock, no network, no config rewrite — run on a STAGED build by the
     * hub-driven updater before anything is swapped. */
    if (strcmp(argv[i], "-selftest") == 0) return run_selftest();
    /* -stage <ver> <variant>: the updater's own stage process (see
     * updater_stage_main); no config, no password, no PID lock. */
    if (strcmp(argv[i], "-stage") == 0)
      return updater_stage_main(i + 1 < argc ? argv[i + 1] : NULL,
                                i + 2 < argc ? argv[i + 2] : NULL);
  }

  /* -selftest (above) stays in the caller's directory: the updater runs a
   * staged build from a scratch subdirectory, against this bot's config. */
  static char self_exe[PATH_MAX];
  if (!instance_dir_enter(self_exe, sizeof(self_exe))) return 1;

  if (do_setup) {
    if (access(CONFIG_FILE, F_OK) == 0) {
      fprintf(stderr, "Error: Config file '%s' already exists.\n", CONFIG_FILE);
      return 1;
    }
    run_config_wizard();
    return 0;
  }

  if (do_passfile) {
    char pass1[MAX_PASS], pass2[MAX_PASS];
    cli_header("ircbot", BOT_VERSION, "password file");
    cli_note("%s holds the config password, bound to this machine, so the bot starts "
             "without typing it.", PASS_FILE);
    printf("\n");
    do {
      cli_ask_secret("password", pass1, sizeof(pass1));
      if (!pass1[0]) {
        cli_err("the password cannot be empty");
        return 1;
      }
      cli_ask_secret("confirm", pass2, sizeof(pass2));
      if (strcmp(pass1, pass2) != 0) cli_err("the passwords do not match: again");
    } while (strcmp(pass1, pass2) != 0);

    bool ok = passfile_create(PASS_FILE, pass1);
    memset(pass1, 0, sizeof(pass1));
    memset(pass2, 0, sizeof(pass2));
    if (ok) {
      cli_ok("wrote %s (0600, bound to this machine)", PASS_FILE);
      cli_kv("next", "./ircbot");
      printf("\n");
      return 0;
    }
    cli_err("could not write %s", PASS_FILE);
    return 1;
  }

  if (access(CONFIG_FILE, F_OK) != 0) {
    fprintf(stderr, "No config file found. First run: ./ircbot -setup\n");
    return 1;
  }

  /* Password resolution: .ircbot.pass → stdin prompt */
  char startup_password[MAX_PASS];
  memset(startup_password, 0, sizeof(startup_password));

  if (!passfile_load(PASS_FILE, startup_password, sizeof(startup_password))) {
    get_password("Config Password", startup_password, sizeof(startup_password));
    if (!startup_password[0]) {
      fprintf(stderr, "No password provided.\n");
      return 1;
    }
  }

  if (do_identity) return run_identity(startup_password);

  if (updater_install_in_progress()) {
    fprintf(stderr, "An upgrade is installing here; not starting\n");
    return 0;
  }
  updater_stage_boot_clean();
  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  fflush(stdout); /* or the buffered lines are written again by the fork */
  daemonize();

  ssl_init_openssl();

  int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0600);
  if (pid_fd == -1) {
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
    /* Read existing PID to report the conflict clearly */
    char existing[16] = "";
    if (read(pid_fd, existing, sizeof(existing) - 1) > 0) {
      existing[strcspn(existing, "\n")] = '\0';
      fprintf(stderr, "Already running (pid %s) — %s\n", existing, PID_FILE);
    } else {
      fprintf(stderr, "Already running — %s locked\n", PID_FILE);
    }
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  /* Truncate then write so no stale bytes remain if new PID is shorter */
  if (ftruncate(pid_fd, 0) < 0) {
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  char pid_str[16];
  snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
  if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }

  bot_state_t state;
  state_init(&state);
  state.pid_fd = pid_fd;
  snprintf(state.executable_path, sizeof(state.executable_path), "%s", self_exe);
  setup_signals();

  if (!config_load(&state, startup_password, CONFIG_FILE)) {
    close(pid_fd);
    remove(PID_FILE);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  /* Lock the raw key material into RAM so it cannot be swapped to disk. */
  mlock(state.hub_key_raw, sizeof(state.hub_key_raw));
  /* XOR-protect the password in memory after successful load */
  bot_set_startup_pass(&state, startup_password);
  memset(startup_password, 0, sizeof(startup_password));
  state.server_list[state.server_count] = NULL;

  // --- MAIN LOOP ---
  while (!(state.status & S_DIE) && !g_shutdown_flag) {
    irc_check_status(&state);
    channel_manager_check_joins(&state);
    commands_activity_tick(&state, time(NULL));
    chanenf_tick(&state);
    hub_client_upgrade_report_tick(&state);
    if (updater_cron_tick(state.executable_path)) hub_client_send_presence(&state, true);
    updater_standalone_tick(&state);
    hub_client_stage_tick(&state);

    /* Debounced config flush.  auth_mark_used() sets config_dirty whenever it
     * bumps last_seen / last_used, which happens on every successful admin
     * auth; writing on each one would cost a full config rewrite (PBKDF2
     * included) per command.  Flush at most once every
     * CONFIG_WRITE_DEBOUNCE_S seconds instead.  select() below has a 1 s
     * timeout, so this is evaluated at least once a second.
     *
     * Local writer on purpose: a config push per admin command would be
     * mesh sync traffic for every command.  The times reach the hub as
     * CMD_ACTIVITY instead, once per record per clock hour (auth_mark_used).
     * Records that the hub is authoritative for still propagate via their
     * own paths (hub_client_push_admin_delta on +admin/-admin, etc.).
     *
     * The cleanup path after this loop calls config_write_with_state_pass()
     * unconditionally, so a still-dirty flag is flushed on clean shutdown. */
    {
      time_t cfg_now = time(NULL);
      if (state.config_dirty &&
          (cfg_now - state.last_config_write) >= CONFIG_WRITE_DEBOUNCE_S) {
        config_write_local_with_state_pass(&state);
        state.config_dirty = false;
        state.last_config_write = cfg_now;
      }
    }

    dcc_check_timeouts(&state);

    // --- HUB GATEKEEPER ---
    // Only execute hub logic if we actually have hubs configured
    if (state.hub_count > 0) {
      hub_client_connect(&state);   // Attempts connection if needed
      hub_client_heartbeat(&state); // Sends pings if authenticated
      hub_client_user_chan_tick(&state); // unanswered person requests -> ~B2
      chan_own_tick(&state);             // our own unanswered requests -> ~B2
      invite_check_tick(&state);         // invites whose WHO never came back
    }

    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    int max_fd = -1;

    // Add IRC socket to select
    if (state.server_fd != -1) {
      FD_SET(state.server_fd, &read_fds);
      if (state.server_fd > max_fd)
        max_fd = state.server_fd;
    }

    // Hub Socket (Only if it's actually active)
    if (state.hub_count > 0 && state.hub_fd != -1) {
      FD_SET(state.hub_fd, &read_fds);
      if (!state.hub_connected) {
        FD_SET(state.hub_fd, &write_fds);
      }
      if (state.hub_fd > max_fd)
        max_fd = state.hub_fd;
    }

    /* Lines wait in the send queue and pacing allows one: wake as soon as
     * the socket is writable.  Otherwise the 1 s select timeout below is the
     * tick that drains them. */
    if (state.server_fd != -1 && sendq_ready(&state)) {
      FD_SET(state.server_fd, &write_fds);
      if (state.server_fd > max_fd)
        max_fd = state.server_fd;
    }

    // DCC chats (connect in progress, or open)
    dcc_fill_fds(&state, &read_fds, &write_fds, &max_fd);
    // An IRC dial in flight (connect, then TLS)
    irc_dial_fill_fds(&state, &read_fds, &write_fds, &max_fd);

    struct timeval tv = {1, 0}; // 1 second timeout
    /* Lines waiting for credit: wake exactly when the next one may go (0 =
     * now), never later than the 1 s tick. */
    if (state.server_fd != -1) {
      int wait_ms = sendq_next_ms(&state);
      if (wait_ms >= 0 && wait_ms < 1000) {
        tv.tv_sec = 0;
        tv.tv_usec = wait_ms * 1000;
      }
    }
    if (max_fd == -1) {
      select(0, NULL, NULL, NULL, &tv);
      continue;
    }

    int activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &tv);

    if (activity > 0) {
      // Handle IRC Data
      if (state.server_fd != -1 && fd_isset(state.server_fd, &read_fds)) {
        irc_handle_read(&state);
      }

      // Handle Hub Async Connection Completion
      if (state.hub_fd != -1 && !state.hub_connected &&
          fd_isset(state.hub_fd, &write_fds)) {
        hub_client_dial_ready(&state);
      }

      // Handle Hub Incoming Data (Pongs, Configs, etc.)
      if (state.hub_fd != -1 && fd_isset(state.hub_fd, &read_fds)) {
        hub_client_process(&state);
      }

      dcc_process(&state, &read_fds, &write_fds);
      irc_dial_process(&state, &read_fds, &write_fds);
    }

    /* Paced output: whatever the queue may send now.  The select() timeout
     * above is sized to the next credit, so lines leave on time. */
    if (state.server_fd != -1)
      sendq_drain(&state);
  }

  // --- CLEANUP ---
  dcc_close_all(&state, "Bot shutting down.");
  config_write_with_state_pass(&state);
  irc_disconnect(&state);
  if (state.hub_fd != -1)
    close(state.hub_fd);
  state_destroy(&state);
  config_key_forget();
#ifdef HAVE_CURL
  curl_global_cleanup();
#endif
  /* Unlink while the flock is still held, then release it: the locked pid
   * file is what marks this bot as running, so a replacement that starts in
   * this window is refused rather than having its own pid file unlinked by
   * the copy on its way out (which would hide it from process control and
   * let a third copy start on the same identity).  Same order as irchub. */
  remove(PID_FILE);
  close(state.pid_fd);
  return 0;
}
