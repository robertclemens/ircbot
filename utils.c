#include <arpa/inet.h>
#include <ctype.h>
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>

#include "bot.h"

void bot_set_startup_pass(bot_state_t *s, const char *pass) {
  /* Store plaintext and lock the page into RAM so it cannot be swapped.
   * See the threat-model comment on bot_state_t.startup_password in bot.h. */
  size_t n = pass ? strlen(pass) : 0;
  if (n >= MAX_PASS) n = MAX_PASS - 1;
  memcpy(s->startup_password, pass ? pass : "", n);
  memset(s->startup_password + n, 0, MAX_PASS - n);
  mlock(s->startup_password, MAX_PASS);
}

void bot_get_startup_pass(const bot_state_t *s, char out[MAX_PASS]) {
  memcpy(out, s->startup_password, MAX_PASS);
  out[MAX_PASS - 1] = '\0';
}

bool bot_has_startup_pass(const bot_state_t *s) {
  return s->startup_password[0] != '\0';
}

void config_write_with_state_pass(bot_state_t *s) {
  char pass[MAX_PASS];
  bot_get_startup_pass(s, pass);
  config_write(s, pass);
  OPENSSL_cleanse(pass, MAX_PASS);
}

void config_write_local_with_state_pass(bot_state_t *s) {
  char pass[MAX_PASS];
  bot_get_startup_pass(s, pass);
  config_write_local(s, pass);
  OPENSSL_cleanse(pass, MAX_PASS);
}

_Noreturn void handle_fatal_error(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}


/* ---- Host capability probe (used by the hub-driven upgrade path) --------
 * Both answers describe the RUNNING binary, not the machine's capabilities in
 * the abstract: a bot reports what it can be replaced with.  The arch comes
 * from uname(2) so it matches the manifest's `uname -m` spelling; the libc is
 * decided at compile time because the binary is already linked against one and
 * musl publishes no runtime identifier. */
void updater_host_arch(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
  struct utsname u;
  if (uname(&u) == 0 && u.machine[0])
    snprintf(out, out_size, "%s", u.machine);
  else
    snprintf(out, out_size, "unknown");
}

void updater_host_libc(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
#if defined(__GLIBC__)
  snprintf(out, out_size, "gnu");
#elif defined(__linux__)
  snprintf(out, out_size, "musl");
#else
  snprintf(out, out_size, "unknown");
#endif
}

/* The variant this binary was built from.  The Rust twin answers "rs"; both
 * are wire- and config-compatible, so a node may be flipped either way. */
const char *updater_host_variant(void) { return "c"; }

static int local_strverscmp(const char *s1, const char *s2) {
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  int state;
  unsigned char c1, c2;

  while ((c1 = *p1++) == (c2 = *p2++)) {
    if (c1 == '\0') return 0;
  }
  p1--;
  p2--;

  if (isdigit(c1) && isdigit(c2)) {
    state = 0;
    while (1) {
      if (state == 0) {
        if (c1 > c2)
          state = 1;
        else if (c1 < c2)
          state = -1;
      }
      if (!isdigit(*p1))
        c1 = 0;
      else
        c1 = *p1++;
      if (!isdigit(*p2))
        c2 = 0;
      else
        c2 = *p2++;
      if (!c1 && !c2) break;
      if (c1 == 0 && c2 != 0) return -1;
      if (c1 != 0 && c2 == 0) return 1;
    }
    return state;
  }
  return (int)p1[0] - (int)p2[0];
}

/* Release manifests spell versions with a leading 'v' ("v2.3.0") while
 * BOT_VERSION does not ("2.3.0"), and an admin may type either.  Compare them
 * on the numeric part alone: local_strverscmp("v0.0.1", "2.3.0") would
 * otherwise compare 'v' against '2' and report a downgrade as an upgrade,
 * which is exactly what the downgrade guard exists to stop. */
static const char *version_strip_v(const char *v) {
  if (!v) return "";
  return (*v == 'v' || *v == 'V') ? v + 1 : v;
}

/* Exported: the hub-upgrade handlers in hub_client.c compare the target
 * and min_from versions the hub sends against BOT_VERSION. */
int updater_version_cmp(const char *a, const char *b) {
  return local_strverscmp(version_strip_v(a), version_strip_v(b));
}

static bool version_eq(const char *a, const char *b) {
  return strcasecmp(version_strip_v(a), version_strip_v(b)) == 0;
}

/* ---- Upgrade hand-off marker -------------------------------------------
 * exec() throws away everything the old process knew, so the upgrade id and
 * the version we were aiming at are left in a file for the new binary to
 * find.  It is read exactly once, on the first authenticated hub link after
 * the restart, and removed there — see hub_client_report_upgrade_result(). */
bool upgrade_marker_write(const char *upgrade_id, const char *target_ver) {
  if (!upgrade_id || !target_ver) return false;
  int fd = open(UPGRADE_MARKER_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0600);
  if (fd < 0) return false;
  char line[256];
  int n = snprintf(line, sizeof(line), "%s|%s\n", upgrade_id, target_ver);
  bool ok = (n > 0 && n < (int)sizeof(line) && write(fd, line, (size_t)n) == n);
  if (close(fd) != 0) ok = false;
  if (!ok) remove(UPGRADE_MARKER_FILE);
  return ok;
}

/* Read and consume the marker.  Returns false when no upgrade is pending,
 * which is the normal case for every ordinary start. */
bool updater_take_pending_upgrade(char *id_out, size_t id_size, char *ver_out,
                                  size_t ver_size) {
  if (!id_out || !ver_out || id_size == 0 || ver_size == 0) return false;
  id_out[0] = ver_out[0] = '\0';

  FILE *f = fopen(UPGRADE_MARKER_FILE, "r");
  if (!f) return false;
  char line[256] = "";
  bool got = (fgets(line, sizeof(line), f) != NULL);
  fclose(f);
  /* Consumed whatever it said: a marker we cannot parse must not be retried
   * on every reconnect for the rest of this process's life. */
  remove(UPGRADE_MARKER_FILE);
  if (!got) return false;

  char id[64] = "", ver[64] = "";
  if (sscanf(line, "%63[^|\r\n]|%63[^\r\n]", id, ver) != 2) return false;
  if (!id[0] || !ver[0]) return false;
  snprintf(id_out, id_size, "%s", id);
  snprintf(ver_out, ver_size, "%s", ver);
  return true;
}

/* Put back the binary and config a hub-driven upgrade retained, then restart
 * onto them.  Used for CMD_UPGRADE_ABORT: by the time it arrives the new
 * build is already the running process, so undoing it means another exec. */
bool updater_hub_rollback(bot_state_t *state, const char *reason) {
  if (!state) return false;
  char prev_exe[PATH_MAX + 8], prev_cfg[PATH_MAX];
  if (snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe) ||
      snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", CONFIG_FILE,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg))
    return false;
  if (access(prev_exe, X_OK) != 0) {
    log_message(L_INFO, state,
                "[UPGRADE] Rollback requested (%s) but no retained binary\n",
                reason ? reason : "no reason given");
    return false;
  }

  log_message(L_INFO, state, "[UPGRADE] Rolling back to the retained build: %s\n",
              reason ? reason : "hub aborted the upgrade");
  /* Config first: if the restart races us, the old binary must not come up
   * against a config only the newer build understands. */
  if (access(prev_cfg, R_OK) == 0 && rename(prev_cfg, CONFIG_FILE) != 0)
    log_message(L_INFO, state,
                "[UPGRADE] Could not restore %s; keeping the current one\n",
                prev_cfg);
  if (rename(prev_exe, state->executable_path) != 0) {
    log_message(L_INFO, state, "[UPGRADE] Could not restore %s\n", prev_exe);
    return false;
  }
  remove(UPGRADE_MARKER_FILE);

  irc_printf(state, "QUIT :Upgrade aborted; restoring previous build...\r\n");
  irc_disconnect(state);
  dcc_close_all(state, "Bot rolling back; closing.");
  hub_client_disconnect(state);
  close(state->pid_fd);
  remove(PID_FILE);
  sleep(1);
  execl(state->executable_path, state->executable_path, (char *)NULL);
  handle_fatal_error("execl rollback");
}
#ifdef HAVE_CURL

/* curl 7.85 replaced the bitmask protocol options with string ones and marked
 * the old pair deprecated; Rocky 8's 7.61 has only the bitmask.  Pick at
 * compile time so both build warning-free. */
#if LIBCURL_VERSION_NUM >= 0x075500
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS_STR, "https,file");                \
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS_STR, "https");               \
  } while (0)
#else
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_FILE);\
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);           \
  } while (0)
#endif

/* A statically linked release binary carries the CA-bundle path of the distro
 * it was built on (Alpine: /etc/ssl/certs/ca-certificates.crt), which RHEL /
 * Rocky / Fedora do not have — every https fetch would then fail closed.  If
 * that compiled-in bundle is missing here, point curl at the first readable
 * bundle this host does have.  A distro-built (dynamic) libcurl's default is
 * right for its own host and is left alone.  Peer verification stays on
 * either way; this only chooses which trust store it uses. */
static void updater_set_ca(CURL *h) {
#if LIBCURL_VERSION_NUM >= 0x074600 /* 7.70: curl_version_info()->cainfo */
  static const char *const bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt",               /* Debian/Ubuntu/Alpine */
      "/etc/pki/tls/certs/ca-bundle.crt",                 /* RHEL/Rocky/Fedora    */
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* RHEL (extracted)     */
      "/etc/ssl/ca-bundle.pem",                           /* openSUSE             */
      "/etc/ssl/cert.pem",                                /* Alpine/BSD           */
  };
  const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
  if (vi && vi->age >= CURLVERSION_SEVENTH && vi->cainfo &&
      access(vi->cainfo, R_OK) == 0)
    return;
  for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++) {
    if (access(bundles[i], R_OK) == 0) {
      curl_easy_setopt(h, CURLOPT_CAINFO, bundles[i]);
      return;
    }
  }
#else
  (void)h;
#endif
}

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  http_response_t *mem = (http_response_t *)userp;

  char *ptr = realloc(mem->buffer, mem->size + realsize + 1);
  if (ptr == NULL) {
    printf("ERROR: not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->buffer = ptr;
  memcpy(&(mem->buffer[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->buffer[mem->size] = 0;

  return realsize;
}
static size_t write_file_callback(void *ptr, size_t size, size_t nmemb,
                                  FILE *stream) {
  return fwrite(ptr, size, nmemb, stream);
}

static bool fetch_url(const char *url, http_response_t *response) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) return false;

  response->buffer = malloc(1);
  response->size = 0;

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
  /* Fail-closed transport: a 404 page is not a manifest.  Without
   * FAILONERROR curl reports CURLE_OK for a 4xx/5xx and hands the error body
   * to the caller, which is how a missing release tree reached the signature
   * check as "release manifest signature INVALID" instead of a clean
   * "not found".  The protocol allow-list keeps a redirect from walking the
   * updater onto scp://, ftp:// or any other scheme curl was built with. */
  curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(curl_handle);
  updater_set_ca(curl_handle);

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  return (res == CURLE_OK);
}

static bool download_file(const char *url, const char *outfile) {
  CURL *curl = curl_easy_init();
  if (!curl) return false;

  FILE *fp = fopen(outfile, "wb");
  if (!fp) {
    curl_easy_cleanup(curl);
    return false;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  /* Fail-closed transport: a 404 page is not a manifest.  Without
   * FAILONERROR curl reports CURLE_OK for a 4xx/5xx and hands the error body
   * to the caller, which is how a missing release tree reached the signature
   * check as "release manifest signature INVALID" instead of a clean
   * "not found".  The protocol allow-list keeps a redirect from walking the
   * updater onto scp://, ftp:// or any other scheme curl was built with. */
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(curl);
  updater_set_ca(curl);


  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  fclose(fp);

  return (res == CURLE_OK);
}

static bool verify_sha256(const char *filepath, const char *expected_hash) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  EVP_MD_CTX *ctx;
  const EVP_MD *md;

  ctx = EVP_MD_CTX_new();
  md = EVP_sha256();
  if (ctx == NULL || md == NULL) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_DigestInit_ex(ctx, md, NULL)) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  FILE *f = fopen(filepath, "rb");
  if (!f) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  unsigned char buffer[4096];
  size_t bytes_read = 0;
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
    if (1 != EVP_DigestUpdate(ctx, buffer, bytes_read)) {
      EVP_MD_CTX_free(ctx);
      fclose(f);
      return false;
    }
  }
  if (1 != EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return false;
  }
  EVP_MD_CTX_free(ctx);
  fclose(f);

  char hex_hash[EVP_MAX_MD_SIZE * 2 + 1];
  int offset = 0;
  for (unsigned int i = 0; i < hash_len; i++) {
    int written = snprintf(hex_hash + offset,
                           sizeof(hex_hash) - (size_t)offset,
                           "%02x", hash[i]);
    if (written > 0)
      offset += written;
  }
  hex_hash[offset] = '\0';

  return (strcasecmp(hex_hash, expected_hash) == 0);
}

static bool validate_dependency_name(const char *dep) {
  if (!dep || strlen(dep) == 0) return false;
  if (strlen(dep) > 64) return false;

  for (const char *p = dep; *p; p++) {
    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.' && *p != '+') {
      return false;
    }
  }
  return true;
}

static bool check_dependency(const char *dep) {
  if (!validate_dependency_name(dep)) {
      return false;
  }

  char command[256];

  if (strcmp(dep, "gcc") == 0 || strcmp(dep, "make") == 0 ||
      strcmp(dep, "tar") == 0 || strcmp(dep, "bash") == 0) {
    snprintf(command, sizeof(command), "command -v %s >/dev/null 2>&1", dep);
  } else {
    snprintf(command, sizeof(command),
             "pkg-config --exists %s >/dev/null 2>&1 || "
             "echo '#include <%s.h>' | gcc -E - >/dev/null 2>&1",
             dep, dep);
  }
  return (system(command) == 0);
}

static bool sanitize_filename(const char *input, char *output, size_t output_size) {
  if (!input || !output || output_size == 0) return false;

  size_t len = 0;
  for (const char *p = input; *p && len < output_size - 1; p++) {
    if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.') {
      output[len++] = *p;
    }
  }
  output[len] = '\0';

  if (len < 8 || strcmp(output + len - 7, ".tar.gz") != 0) {
    return false;
  }
  return len > 0;
}

/* A non-empty IRCBOT_UPDATE_BASE overrides the compiled release base URL.  The
 * sandboxed testnet uses it to read a local ircbot-releases tree via a file://
 * URL with no outbound network.  When set, validate_url() also accepts URLs
 * that begin with this base; the Ed25519 signature and SHA-256 checks stay
 * fully active — only the github/https host allow-list is relaxed, and only for
 * this explicitly-configured local base. */
static const char *updater_env_base(void) {
  const char *b = getenv("IRCBOT_UPDATE_BASE");
  return (b && b[0]) ? b : NULL;
}

static bool validate_url(const char *url) {
  if (!url) return false;
  /* Reject shell metacharacters regardless of source. */
  if (strstr(url, ";") || strstr(url, "|") || strstr(url, "&") ||
      strstr(url, "`") || strstr(url, "$")) {
    return false;
  }
  /* Local-source override: accept only URLs under the configured base. */
  const char *ebase = updater_env_base();
  if (ebase && strncmp(url, ebase, strlen(ebase)) == 0) {
    return true;
  }
  if (strncmp(url, "https://", 8) != 0) {
    return false;
  }
  if (strstr(url, "github.com") == NULL &&
      strstr(url, "githubusercontent.com") == NULL) {
    return false;
  }
  return true;
}

/* Fetch the release manifest AND its detached Ed25519 signature, then verify
 * the signature against the compiled-in public key (BOT_UPDATE_PUBKEY_B64)
 * over the EXACT manifest bytes received.  Returns the verified, NUL-terminated
 * manifest text on success (caller frees); returns NULL on ANY failure and
 * sets *err to a short human-readable reason.  Fail-closed: an unconfigured,
 * unreachable, or invalid signature all yield NULL so no unauthenticated
 * manifest is ever parsed, downloaded from, or executed. */
static char *fetch_verified_manifest(const char **err) {
  *err = NULL;

  /* Pinned key, unless the local-source override is active AND a test key is
   * provided (sandbox only): IRCBOT_UPDATE_PUBKEY is honored solely when
   * IRCBOT_UPDATE_BASE is set, so production always uses the compiled key. */
  const char *pubkey_b64 = BOT_UPDATE_PUBKEY_B64;
  if (updater_env_base()) {
    const char *ep = getenv("IRCBOT_UPDATE_PUBKEY");
    if (ep && ep[0]) pubkey_b64 = ep;
  }

  /* Empty pinned key = updater intentionally disabled. */
  if (pubkey_b64[0] == '\0') {
    *err = "self-updater disabled (no signing key configured)";
    return NULL;
  }

  /* Decode the Ed25519 public key (must be exactly 32 raw bytes). */
  int publen = 0;
  unsigned char *pub = base64_decode(pubkey_b64, &publen);
  if (!pub || publen != 32) {
    if (pub) free(pub);
    *err = "configured update public key is malformed";
    return NULL;
  }

  /* Fetch the manifest. */
  http_response_t man;
  man.buffer = NULL;
  man.size = 0;
  const char *ebase = updater_env_base();
  char man_url[1024], sig_url[1024];
  if (ebase) {
    snprintf(man_url, sizeof(man_url), "%s/releases.txt", ebase);
    snprintf(sig_url, sizeof(sig_url), "%s/releases.sig", ebase);
  } else {
    snprintf(man_url, sizeof(man_url), "%s", BOT_UPDATE_URL);
    snprintf(sig_url, sizeof(sig_url), "%s", BOT_UPDATE_SIG_URL);
  }
  if (!fetch_url(man_url, &man)) {
    free(pub);
    if (man.buffer) free(man.buffer);
    *err = "failed to download release manifest";
    return NULL;
  }

  /* Fetch the detached signature (base64 of 64 raw bytes). */
  http_response_t sig;
  sig.buffer = NULL;
  sig.size = 0;
  if (!fetch_url(sig_url, &sig)) {
    free(pub);
    if (man.buffer) free(man.buffer);
    if (sig.buffer) free(sig.buffer);
    *err = "failed to download release signature (releases.txt.sig)";
    return NULL;
  }

  int siglen = 0;
  unsigned char *sigbytes = base64_decode(sig.buffer, &siglen);
  bool ok = (sigbytes && siglen == 64 &&
             crypto_ed25519_verify(pub, (const unsigned char *)man.buffer,
                                   man.size, sigbytes));

  free(pub);
  if (sigbytes) free(sigbytes);
  if (sig.buffer) free(sig.buffer);

  if (!ok) {
    if (man.buffer) free(man.buffer);
    *err = "release manifest signature INVALID — possible tampering";
    return NULL;
  }
  return man.buffer; /* verified manifest; caller frees */
}

void updater_check_for_updates(bot_state_t *state, const char *nick) {
  log_message(L_DEBUG, state, "[DEBUG] updater_check_for_updates called.\n");

  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    irc_printf(state, "PRIVMSG %s :Update check failed: %s.\r\n",
               nick, verr ? verr : "unknown error");
    return;
  }
  http_response_t response;
  response.buffer = manifest; /* verified bytes; existing parse/free below */
  response.size = 0;

  irc_printf(state, "PRIVMSG %s :--- Available Updates (Current: %s) ---\r\n",
             nick, BOT_VERSION);
  char *saveptr_line;
  char *line = strtok_r(response.buffer, "\n", &saveptr_line);
  int updates_found = 0;

  while (line) {
    if (line[0] == '#') {
      line = strtok_r(NULL, "\n", &saveptr_line);
      continue;
    }

    char version[64], date[64], url[512], hash[128], deps[256];
    if (sscanf(line, "%63s %63s %511s %127s %255s", version, date, url, hash,
               deps) == 5) {
      if (updater_version_cmp(version, BOT_VERSION) > 0) {
        updates_found++;
        char deps_status[512] = "[OK]";
        bool all_deps_ok = true;

        char deps_copy[256];
        snprintf(deps_copy, sizeof(deps_copy), "%s", deps);
        char *saveptr_dep;
        char *dep = strtok_r(deps_copy, ",", &saveptr_dep);

        while (dep) {
          if (!check_dependency(dep)) {
            if (all_deps_ok) {
              snprintf(deps_status, sizeof(deps_status), "[FAILED: %s", dep);
            } else {
              strncat(deps_status, ", ",
                      sizeof(deps_status) - strlen(deps_status) - 1);
              strncat(deps_status, dep,
                      sizeof(deps_status) - strlen(deps_status) - 1);
            }
            all_deps_ok = false;
          }
          dep = strtok_r(NULL, ",", &saveptr_dep);
        }
        if (!all_deps_ok)
          strncat(deps_status, "]",
                  sizeof(deps_status) - strlen(deps_status) - 1);

        irc_printf(state, "PRIVMSG %s :%s (%s) - Dependencies: %s\r\n", nick,
                   version, date, deps_status);
      }
    }
    line = strtok_r(NULL, "\n", &saveptr_line);
  }

  if (updates_found == 0) {
    irc_printf(state, "PRIVMSG %s :Bot is up-to-date.\r\n", nick);
  } else {
    irc_printf(
        state,
        "PRIVMSG %s :To upgrade, type: update <version>. IE: update v2.0.0\r\n",
        nick);
  }

  if (response.buffer) {
    free(response.buffer);
  }
}

/* ircbot -checkupdate [variant]: fetch the release manifest and its signature
 * exactly as a hub-driven upgrade does — the release tree <base>/<variant>,
 * the compiled-in base and pinned key unless IRCBOT_UPDATE_BASE says
 * otherwise — verify one against the other, and report.  Nothing past the
 * manifest is downloaded and nothing is installed, so an operator (or the
 * testnet) can prove a host reaches and trusts the real release channel —
 * TLS, CA store, pinned key — without upgrading anything.  0 = verified. */
int updater_check_cli(const char *variant) {
  const char *want = (variant && variant[0]) ? variant : updater_host_variant();
  if (strpbrk(want, "/;|&`$ \t\r\n") || strlen(want) > 7) {
    printf("checkupdate: FAIL malformed variant\n");
    return 1;
  }
  if (!updater_env_base()) {
    char tree[600];
    snprintf(tree, sizeof(tree), "%s/%s", BOT_UPDATE_BASE, want);
    setenv("IRCBOT_UPDATE_BASE", tree, 1);
  }
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    printf("checkupdate: FAIL %s (%s)\n", verr ? verr : "manifest fetch failed",
           getenv("IRCBOT_UPDATE_BASE"));
    return 1;
  }
  int rows = 0;
  char newest[64] = "";
  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char version[64];
    if (line[0] == '#' || sscanf(line, "%63s", version) != 1) continue;
    rows++;
    if (!newest[0] || updater_version_cmp(version, newest) > 0)
      snprintf(newest, sizeof(newest), "%s", version);
  }
  free(manifest);
  printf("checkupdate: OK %s manifest verified: %d release row(s), newest %s, "
         "running %s\n",
         want, rows, newest[0] ? newest : "-", BOT_VERSION);
  return 0;
}

void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version_to_install) {
  log_message(L_DEBUG, state,
              "[DEBUG] updater_perform_upgrade called for %s.\n",
              version_to_install);

  http_response_t response;
  char *binary_url = NULL;
  char *expected_hash = NULL;
  char *deps_to_check = NULL;

  /* Downgrade protection: refuse to install anything older than the running
   * build, defeating a replay of an old (but validly signed) manifest that
   * points at a known-vulnerable version. */
  if (updater_version_cmp(version_to_install, BOT_VERSION) < 0) {
    irc_printf(state,
               "PRIVMSG %s :Refusing downgrade: %s is older than the running "
               "version %s.\r\n",
               nick, version_to_install, BOT_VERSION);
    return;
  }

  /* Fetch + Ed25519-verify the manifest before trusting any field in it. */
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    irc_printf(state, "PRIVMSG %s :Upgrade aborted: %s.\r\n",
               nick, verr ? verr : "unknown error");
    return;
  }
  response.buffer = manifest;
  response.size = 0;

  char *saveptr;
  char *line = strtok_r(response.buffer, "\n", &saveptr);

  while (line) {
    char version[64], date[64], url[512], hash[128], deps[256];
    if (sscanf(line, "%63s %63s %511s %127s %255s", version, date, url, hash,
               deps) == 5) {
      if (version_eq(version, version_to_install)) {
        if (!validate_url(url)) {
          irc_printf(state, "PRIVMSG %s :Error: Invalid or untrusted URL in release file.\r\n", nick);
          free(response.buffer);
          return;
        }
        binary_url = strdup(url);
        expected_hash = strdup(hash);
        deps_to_check = strdup(deps);
        break;
      }
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (!binary_url) {
    irc_printf(state,
               "PRIVMSG %s :Error: Version '%s' not found in release file.\r\n",
               nick, version_to_install);
    if (response.buffer) free(response.buffer);
    /* If strdup(url) failed mid-match while hash/deps succeeded, those two are
     * non-NULL here; free(NULL) is a no-op for the normal not-found path. */
    free(expected_hash);
    free(deps_to_check);
    return;
  }
  if (response.buffer) {
    free(response.buffer);
    response.buffer = NULL;
  }

  char failed_deps[256] = "";
  bool all_deps_ok = true;
  char *dep = strtok_r(deps_to_check, ",", &saveptr);
  while (dep) {
    if (!check_dependency(dep)) {
      if (!all_deps_ok)
        strncat(failed_deps, ", ",
                sizeof(failed_deps) - strlen(failed_deps) - 1);
      strncat(failed_deps, dep, sizeof(failed_deps) - strlen(failed_deps) - 1);
      all_deps_ok = false;
    }
    dep = strtok_r(NULL, ",", &saveptr);
  }
  free(deps_to_check);

  if (!all_deps_ok) {
    irc_printf(
        state,
        "PRIVMSG %s :Error: Cannot upgrade. Missing dependencies: %s\r\n", nick,
        failed_deps);
    free(binary_url);
    free(expected_hash);
    return;
  }

  const char *url_filename = strrchr(binary_url, '/');
  if (url_filename) {
    url_filename++;
  } else {
    url_filename = "ircbot.tar.gz";
  }
  char safe_filename[256];
  if (!sanitize_filename(url_filename, safe_filename, sizeof(safe_filename))) {
    irc_printf(state, "PRIVMSG %s :Error: Invalid filename in URL.\r\n", nick);
    free(binary_url);
    free(expected_hash);
    return;
  }

  irc_printf(state, "PRIVMSG %s :Downloading %s...\r\n", nick, safe_filename);
  if (!download_file(binary_url, safe_filename)) {
    irc_printf(state, "PRIVMSG %s :Error: Failed to download new version.\r\n",
               nick);
    free(binary_url);
    free(expected_hash);
    return;
  }

  irc_printf(state, "PRIVMSG %s :Verifying hash...\r\n", nick);
  if (!verify_sha256(safe_filename, expected_hash)) {
    irc_printf(state,
               "PRIVMSG %s :Error: SHA256 hash mismatch! Aborting upgrade.\r\n",
               nick);
    remove(safe_filename);
    free(binary_url);
    free(expected_hash);
    return;
  }

  free(binary_url);
  free(expected_hash);

  char dir_name[256];
  snprintf(dir_name, sizeof(dir_name), "%s", safe_filename);
  char *tar_gz = strstr(dir_name, ".tar.gz");
  if (tar_gz) {
    *tar_gz = '\0';
  } else {
    irc_printf(
        state,
        "PRIVMSG %s :Error: Invalid archive name. Must end in .tar.gz\r\n",
        nick);
    remove(safe_filename);
    return;
  }
  config_write_with_state_pass(state);
  char backup_path[PATH_MAX + 8];
  snprintf(backup_path, sizeof(backup_path), "%s.backup", state->executable_path);
  rename(state->executable_path, backup_path);

  irc_printf(state, "PRIVMSG %s :Hash verified. Creating upgrade script...\r\n",
             nick);

  /* Create with mode 0700 atomically (no umask-dependent world-readable/
   * writable window on a script we are about to exec); fchmod as belt-and-
   * suspenders.  Avoids the TOCTOU between fopen and a later path-based chmod. */
  int up_fd = open("upgrade.sh", O_WRONLY | O_CREAT | O_TRUNC, 0700);
  FILE *f = (up_fd >= 0) ? fdopen(up_fd, "w") : NULL;
  if (!f) {
    if (up_fd >= 0) close(up_fd);
    irc_printf(state,
               "PRIVMSG %s :Error: Could not create upgrade.sh script.\r\n",
               nick);
    remove(safe_filename);
    rename(backup_path, state->executable_path);
    return;
  }

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "set -e\n");
  fprintf(f, "OLD_PID=%d\n", getpid());
  fprintf(f, "echo \"[UPGRADE] Waiting for old process (PID: $OLD_PID) to exit...\"\n");
  fprintf(f, "for i in {1..30}; do\n");
  fprintf(f, "  if ! kill -0 $OLD_PID 2>/dev/null; then\n");
  fprintf(f, "    break\n");
  fprintf(f, "  fi\n");
  fprintf(f, "  sleep 1\n");
  fprintf(f, "done\n");
  fprintf(f, "UPGRADE_DIR=\"./bot_build_tmp\"\n");
  fprintf(f, "rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "mkdir \"$UPGRADE_DIR\"\n");
  fprintf(f, "if [ ! -d \"$UPGRADE_DIR\" ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Could not create build directory.\"\n");
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Unpacking archive...\"\n");
  fprintf(f, "tar -xzf \"%s\" --strip-components=1 -C \"$UPGRADE_DIR\" 2>/dev/null\n", 
          safe_filename);
  fprintf(f, "if [ $? -ne 0 ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Failed to extract archive.\"\n");
  fprintf(f, "  mv \"%s\" \"%s\" 2>/dev/null\n", backup_path, state->executable_path);
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Entering $UPGRADE_DIR and compiling...\"\n");
  fprintf(f, "cd \"$UPGRADE_DIR\"\n");
  fprintf(f, "make clean >/dev/null 2>&1\n");
  fprintf(f, "make 2>&1 | tee make.log\n");
  fprintf(f, "if [ ! -f ircbot ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Make failed. Binary not found.\"\n");
  fprintf(f, "  echo \"[UPGRADE] Restoring backup...\"\n");
  fprintf(f, "  cd ..\n");
  fprintf(f, "  mv \"%s\" \"%s\" 2>/dev/null\n", backup_path, state->executable_path);
  fprintf(f, "  rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "  rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "  rm -f \"%s\"\n", safe_filename);
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Moving new binary into place...\"\n");
  fprintf(f, "mv ircbot \"%s\"\n", state->executable_path);
  fprintf(f, "chmod 700 \"%s\"\n", state->executable_path);
  fprintf(f, "cd ..\n");
  fprintf(f, "echo \"[UPGRADE] Removing old PID file...\"\n");
  fprintf(f, "rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "echo \"[UPGRADE] Removing backup...\"\n");
  fprintf(f, "rm -f \"%s\"\n", backup_path);
  fprintf(f, "echo \"[UPGRADE] Scheduling cleanup...\"\n");
  fprintf(f, "(sleep 5; rm -rf \"$UPGRADE_DIR\" \"%s\" \"./upgrade.sh\" 2>/dev/null) &\n",
          safe_filename);
  fprintf(f, "echo \"[UPGRADE] Restarting bot...\"\n");
  fprintf(f, "exec %s\n", state->executable_path);

  (void)fchmod(fileno(f), 0700);
  fclose(f);

  irc_printf(state, "QUIT :Upgrading to %s...\r\n", version_to_install);
  irc_disconnect(state);
  /* The chats' fds are close-on-exec anyway; this says goodbye first. */
  dcc_close_all(state, "Bot upgrading; closing.");
  close(state->pid_fd);

  sleep(1);

  execl("./upgrade.sh", "./upgrade.sh", NULL);

  perror("execl failed");
  exit(1);
}

/* ======================================================================
 * Hub-driven upgrade (CMD_UPGRADE_COMMIT)
 *
 * A hub-configured bot never upgrades itself from an IRC command (see the
 * gate in commands.c); its hub drives the whole network in a rolling plan.
 * This entry point is kept PARALLEL to updater_perform_upgrade() rather than
 * folded into it: that function's QUIT/exec sequence is delicate and is still
 * the entire story for standalone bots, while this path differs in nearly
 * every other respect —
 *   - no admin nick to answer: progress goes to the log, and the outcome to
 *     the hub as CMD_UPGRADE_RESULT after the restart,
 *   - the artifact is chosen by {kind,arch,libc} rather than "first row with
 *     this version" — a prebuilt binary matching this host beats a source
 *     build (Task 5), and a source build needs its dependencies present,
 *   - the old binary and config are RETAINED as <exe>.prev / <config>.prev,
 *     never deleted, so the hub can order a rollback after the new build is
 *     already running (Task 4).
 * ====================================================================== */

/* Byte-copy with an explicit mode.  Used for the config snapshot, where the
 * original must stay in place (the binary is renamed instead). */
static bool copy_file(const char *src, const char *dst, mode_t mode) {
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0) return false;
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (out < 0) {
    close(in);
    return false;
  }
  char buf[8192];
  bool ok = true;
  ssize_t n;
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w <= 0) {
        ok = false;
        break;
      }
      off += w;
    }
    if (!ok) break;
  }
  if (n < 0) ok = false;
  if (ok && fsync(out) != 0) ok = false;
  close(in);
  if (close(out) != 0) ok = false;
  if (!ok) remove(dst);
  return ok;
}

/* One artifact row of the release manifest.  Columns 1-5 are the legacy
 * format the standalone updater already parses; 6-9 were appended for the
 * network upgrade and are absent from older manifests, which is why they
 * default to a source build that fits anything. */
typedef struct {
  char version[64];
  char url[512];
  char hash[128];
  char deps[256];
  char kind[8];     /* bin | src              */
  char arch[32];    /* x86_64 | any           */
  char libc[16];    /* gnu | musl | any       */
  char min_from[64];/* oldest version this may upgrade FROM; '*' = any */
} manifest_row_t;

/* Does this row's {arch,libc} fit the running host?  "any" fits everything,
 * which is what source tarballs and older manifests carry. */
static bool row_fits_host(const manifest_row_t *r) {
  char arch[32], libc[16];
  updater_host_arch(arch, sizeof(arch));
  updater_host_libc(libc, sizeof(libc));
  if (strcmp(r->arch, "any") != 0 && strcasecmp(r->arch, arch) != 0)
    return false;
  if (strcmp(r->libc, "any") != 0 && strcasecmp(r->libc, libc) != 0)
    return false;
  return true;
}

/* Every dependency the row names must be present (source builds only; a
 * prebuilt binary carries "none").  failed is filled with the missing ones. */
static bool row_deps_ok(const manifest_row_t *r, char *failed, size_t failed_size) {
  if (failed && failed_size) failed[0] = '\0';
  if (strcasecmp(r->deps, "none") == 0) return true;
  char deps_copy[256];
  snprintf(deps_copy, sizeof(deps_copy), "%s", r->deps);
  bool all_ok = true;
  char *saveptr = NULL;
  for (char *dep = strtok_r(deps_copy, ",", &saveptr); dep;
       dep = strtok_r(NULL, ",", &saveptr)) {
    if (check_dependency(dep)) continue;
    if (failed && failed_size) {
      if (!all_ok) strncat(failed, ", ", failed_size - strlen(failed) - 1);
      strncat(failed, dep, failed_size - strlen(failed) - 1);
    }
    all_ok = false;
  }
  return all_ok;
}

/* Choose the artifact for `version`: a usable prebuilt binary for this host
 * wins, otherwise a source tarball whose build dependencies are installed.
 * `manifest` is consumed (strtok_r).  reason explains an empty result. */
static bool manifest_select(char *manifest, const char *version,
                            manifest_row_t *out, char *reason,
                            size_t reason_size) {
  bool have_pick = false;
  char missing[256] = "";
  snprintf(reason, reason_size, "requested version is not in the manifest");

  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '#' || line[0] == '\0') continue;

    manifest_row_t row;
    memset(&row, 0, sizeof(row));
    char date[64];
    /* Columns 6-9 are optional: an older 5-column manifest yields a source
     * artifact that fits any host and may be installed from any version. */
    snprintf(row.kind, sizeof(row.kind), "src");
    snprintf(row.arch, sizeof(row.arch), "any");
    snprintf(row.libc, sizeof(row.libc), "any");
    snprintf(row.min_from, sizeof(row.min_from), "*");
    int n = sscanf(line, "%63s %63s %511s %127s %255s %7s %31s %15s %63s",
                   row.version, date, row.url, row.hash, row.deps, row.kind,
                   row.arch, row.libc, row.min_from);
    if (n < 5) continue;
    if (!version_eq(row.version, version)) continue;

    if (!validate_url(row.url)) {
      snprintf(reason, reason_size, "untrusted artifact URL in manifest");
      continue;
    }
    if (!row_fits_host(&row)) {
      snprintf(reason, reason_size, "no artifact for this host arch/libc");
      continue;
    }
    if (strcmp(row.min_from, "*") != 0 &&
        updater_version_cmp(BOT_VERSION, row.min_from) < 0) {
      snprintf(reason, reason_size,
               "running version is below the artifact's min_from %s",
               row.min_from);
      continue;
    }
    if (!row_deps_ok(&row, missing, sizeof(missing))) {
      snprintf(reason, reason_size, "missing build dependencies: %s", missing);
      continue;
    }
    /* Usable.  Prefer a prebuilt binary; keep looking only if this is a
     * source row that a later binary row could beat. */
    *out = row;
    have_pick = true;
    if (strcasecmp(row.kind, "bin") == 0) break;
  }

  if (have_pick) reason[0] = '\0';
  return have_pick;
}

/* Write the upgrade script for a hub-driven commit.  `kind` decides the
 * middle of it: a prebuilt binary is unpacked and moved into place, a source
 * tarball is compiled first.  Either way the previous binary stays at
 * <exe>.prev — the hub, not the script, decides whether to keep it. */
static bool write_hub_upgrade_script(const bot_state_t *state, const char *kind,
                                     const char *archive, const char *prev_path) {
  /* 0700 at creation: no umask-dependent window on a script we are about to
   * exec (same reasoning as the standalone path). */
  int fd = open("upgrade.sh", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
  FILE *f = (fd >= 0) ? fdopen(fd, "w") : NULL;
  if (!f) {
    if (fd >= 0) close(fd);
    return false;
  }
  const char *exe = state->executable_path;
  bool is_bin = (strcasecmp(kind, "bin") == 0);

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "set -u\n");
  fprintf(f, "OLD_PID=%d\n", getpid());
  fprintf(f, "for i in $(seq 1 30); do\n");
  fprintf(f, "  kill -0 $OLD_PID 2>/dev/null || break\n");
  fprintf(f, "  sleep 1\n");
  fprintf(f, "done\n");
  fprintf(f, "UPGRADE_DIR=\"./bot_build_tmp\"\n");
  fprintf(f, "rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "mkdir \"$UPGRADE_DIR\" || exit 1\n");
  /* One rollback path for every failure below: put <exe>.prev back and run
   * it, so a bot that cannot upgrade still comes back on the old build. */
  fprintf(f, "rollback() {\n");
  fprintf(f, "  echo \"[UPGRADE] FAILED: $1 — restoring previous build\"\n");
  fprintf(f, "  mv -f \"%s\" \"%s\" 2>/dev/null\n", prev_path, exe);
  fprintf(f, "  rm -f \"%s\" \"%s\"\n", PID_FILE, UPGRADE_MARKER_FILE);
  fprintf(f, "  rm -rf \"$UPGRADE_DIR\" \"%s\"\n", archive);
  fprintf(f, "  exec \"%s\"\n", exe);
  fprintf(f, "}\n");
  fprintf(f, "tar -xzf \"%s\" --strip-components=1 -C \"$UPGRADE_DIR\" "
             "2>/dev/null || rollback \"could not extract artifact\"\n",
          archive);

  if (is_bin) {
    /* Prebuilt: the tarball holds the binary itself, no toolchain needed. */
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/ircbot\"\n");
    fprintf(f, "[ -f \"$NEW_BIN\" ] || rollback \"artifact contains no ircbot binary\"\n");
    fprintf(f, "chmod 700 \"$NEW_BIN\"\n");
    /* No "run it once" probe here: ircbot has no --version flag and starting
     * a second instance would fight the one we are replacing.  The hub is the
     * health monitor — it waits for this node to reappear announcing the new
     * version and sends CMD_UPGRADE_ABORT if it never does. */
    fprintf(f, "[ -x \"$NEW_BIN\" ] || rollback \"artifact binary is not executable\"\n");
  } else {
    fprintf(f, "cd \"$UPGRADE_DIR\" || rollback \"build directory vanished\"\n");
    fprintf(f, "make clean >/dev/null 2>&1\n");
    fprintf(f, "make >make.log 2>&1\n");
    fprintf(f, "cd ..\n");
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/ircbot\"\n");
    fprintf(f, "[ -f \"$NEW_BIN\" ] || rollback \"build failed (see $UPGRADE_DIR/make.log)\"\n");
  }

  /* Atomic same-directory rename into place; <exe> was already renamed to
   * <exe>.prev, which we keep for the hub's rollback window. */
  fprintf(f, "mv -f \"$NEW_BIN\" \"%s\" || rollback \"could not install new binary\"\n", exe);
  fprintf(f, "chmod 700 \"%s\"\n", exe);
  fprintf(f, "rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "(sleep 5; rm -rf \"$UPGRADE_DIR\" \"%s\" \"./upgrade.sh\" 2>/dev/null) &\n",
          archive);
  fprintf(f, "exec \"%s\"\n", exe);

  (void)fchmod(fileno(f), 0700);
  return fclose(f) == 0;
}

/* Run the upgrade the hub just committed us to.  Returns false with *err set
 * when nothing was touched (the caller answers CMD_UPGRADE_RESULT fail and
 * stays on the current build); on success it does not return — the process is
 * replaced and reports in after the restart. */
bool updater_hub_commit(bot_state_t *state, const char *upgrade_id,
                        const char *target_ver, const char *variant,
                        const char *base, const char **err) {
  *err = NULL;
  if (!state || !upgrade_id || !target_ver) {
    *err = "malformed upgrade command";
    return false;
  }

  /* The hub may point us at a different release base than the compiled-in
   * one (the testnet serves a local ircbot-releases tree).  It travels the
   * same path as the operator-set env var, so signature and hash checks are
   * unchanged — see updater_env_base(). */
  const char *want_variant = (variant && variant[0]) ? variant
                                                     : updater_host_variant();
  if (strpbrk(want_variant, "/;|&`$ \t\r\n") || strlen(want_variant) > 7) {
    *err = "rejected malformed variant from hub";
    return false;
  }
  {
    /* The hub names the release tree ROOT; the variant picks the subtree.
     * That is what lets one network-wide run leave each node on its own kind
     * of build — and lets an admin move a node from the C build to the Rust
     * one by naming the other variant. */
    const char *root = (base && base[0]) ? base : BOT_UPDATE_BASE;
    if (strlen(root) >= 512 || strpbrk(root, ";|&`$ \t\r\n")) {
      *err = "rejected malformed manifest base from hub";
      return false;
    }
    char tree[600];
    if (snprintf(tree, sizeof(tree), "%s/%s", root, want_variant) >=
        (int)sizeof(tree)) {
      *err = "manifest base too long";
      return false;
    }
    setenv("IRCBOT_UPDATE_BASE", tree, 1);
  }

  /* Same downgrade guard as the standalone path: a validly signed but stale
   * manifest must not be able to walk us back onto a known-bad build. */
  if (updater_version_cmp(target_ver, BOT_VERSION) < 0) {
    *err = "refusing downgrade";
    return false;
  }
  /* Nothing to do is a success, not a failure: the hub's rolling plan can
   * then move straight on to the next node. */
  if (updater_version_cmp(target_ver, BOT_VERSION) == 0) {
    *err = "already running the target version";
    return false;
  }
  /* An unattended restart needs the machine-bound password file; without it
   * the new binary would stop at a password prompt with nobody to answer. */
  if (access(PASS_FILE, R_OK) != 0) {
    *err = "no " PASS_FILE "; unattended restart is impossible";
    return false;
  }
  log_message(L_INFO, state, "[UPGRADE] Hub commit %s: %s -> %s (variant %s)\n",
              upgrade_id, BOT_VERSION, target_ver, want_variant);

  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    *err = verr ? verr : "manifest fetch failed";
    return false;
  }

  manifest_row_t row;
  memset(&row, 0, sizeof(row));
  static char why[320];
  bool picked = manifest_select(manifest, target_ver, &row, why, sizeof(why));
  free(manifest);
  if (!picked) {
    *err = why[0] ? why : "no usable artifact";
    return false;
  }

  char archive[256];
  const char *slash = strrchr(row.url, '/');
  if (!sanitize_filename(slash ? slash + 1 : "ircbot.tar.gz", archive,
                         sizeof(archive))) {
    *err = "artifact filename in manifest is not acceptable";
    return false;
  }

  /* Every release artifact is named "<product>-…tar.gz" (see the releases
   * repo README).  A base override that names the OTHER product's tree would
   * otherwise hand this daemon the wrong binary and install it over itself —
   * fail closed here instead, where nothing has been downloaded yet. */
  if (strncmp(archive, "ircbot-", 7) != 0) {
    *err = "manifest artifact is not a ircbot release";
    return false;
  }

  log_message(L_INFO, state, "[UPGRADE] Fetching %s artifact %s\n", row.kind,
              archive);
  if (!download_file(row.url, archive)) {
    *err = "artifact download failed";
    return false;
  }
  if (!verify_sha256(archive, row.hash)) {
    remove(archive);
    *err = "artifact SHA-256 mismatch";
    return false;
  }

  /* Flush the live config, then snapshot the pair we may have to restore.
   * The config is copied (the running bot still needs it); the binary is
   * renamed, which is atomic and leaves <exe>.prev ready for a rollback. */
  config_write_with_state_pass(state);
  char prev_cfg[PATH_MAX];
  char prev_exe[PATH_MAX + 8];
  if (snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", CONFIG_FILE,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg) ||
      snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe)) {
    remove(archive);
    *err = "path too long for rollback snapshot";
    return false;
  }
  if (!copy_file(CONFIG_FILE, prev_cfg, 0600)) {
    remove(archive);
    *err = "could not snapshot config for rollback";
    return false;
  }
  if (rename(state->executable_path, prev_exe) != 0) {
    remove(prev_cfg);
    remove(archive);
    *err = "could not retain previous binary";
    return false;
  }
  /* From here a failure is the script's to handle: it restores <exe>.prev
   * and restarts the old build rather than leaving the node with no binary. */
  if (!upgrade_marker_write(upgrade_id, target_ver) ||
      !write_hub_upgrade_script(state, row.kind, archive, prev_exe)) {
    remove(UPGRADE_MARKER_FILE);
    rename(prev_exe, state->executable_path);
    remove(prev_cfg);
    remove(archive);
    *err = "could not stage the upgrade script";
    return false;
  }

  log_message(L_INFO, state, "[UPGRADE] Installing %s and restarting\n",
              target_ver);
  irc_printf(state, "QUIT :Upgrading to %s (hub-managed)...\r\n", target_ver);
  irc_disconnect(state);
  dcc_close_all(state, "Bot upgrading; closing.");
  hub_client_disconnect(state);
  close(state->pid_fd);
  sleep(1);

  execl("./upgrade.sh", "./upgrade.sh", NULL);
  /* exec failed: put the old binary back so the node is not left dead. */
  rename(prev_exe, state->executable_path);
  remove(UPGRADE_MARKER_FILE);
  handle_fatal_error("execl upgrade.sh");
}
#else /* !HAVE_CURL */
int updater_check_cli(const char *variant) {
  (void)variant;
  printf("checkupdate: FAIL bot compiled without curl support\n");
  return 1;
}

void updater_check_for_updates(bot_state_t *state, const char *nick) {
  irc_printf(state, "PRIVMSG %s :Update feature unavailable - bot compiled without curl support.\r\n", nick);
}

void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version_to_install) {
  (void)version_to_install;  /* Unused parameter */
  irc_printf(state, "PRIVMSG %s :Update feature unavailable - bot compiled without curl support.\r\n", nick);
}

bool updater_hub_commit(bot_state_t *state, const char *upgrade_id,
                        const char *target_ver, const char *variant,
                        const char *base, const char **err) {
  (void)state; (void)upgrade_id; (void)target_ver; (void)variant; (void)base;
  *err = "bot compiled without curl support";
  return false;
}
#endif /* HAVE_CURL */
