#define _POSIX_C_SOURCE 200809L
#include "bot.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static hub_auth_state_t auth_state = HUB_AUTH_NONE;
static time_t last_pong_sent = 0;

void hub_client_init(bot_state_t *state) {
  state->hub_fd = -1;
  state->hub_connected = false;
  state->hub_connecting = false;
  state->hub_authenticated = false;
  state->last_hub_connect_attempt = 0;
  state->last_hub_ping_time = 0;
  state->last_hub_activity = 0;
  state->hub_connect_time = 0;
  memset(state->hub_session_key, 0, 32);
  auth_state = HUB_AUTH_NONE;
  last_pong_sent = 0;
}

void hub_client_on_connect(bot_state_t *state) {
  if (state->hub_count > 0) {
    hub_client_connect(state);
  }
}

/* Copy the raw key halves from the pre-decoded, mlock'd hub_key_raw buffer.
 * Avoids repeated base64 decoding and keeps the key out of new heap regions.
 * This is the bot's single identity key: hub handshake, ~A2/~A2K admin
 * transport and ~B2 bot-to-bot all use it.  Callers wipe the outputs. */
bool bot_key_decode(bot_state_t *state, unsigned char ed_priv[32],
                    unsigned char x_priv[32]) {
  /* Zero check: if hub_key_raw was never populated, fall back to base64 decode
   * (handles the first handshake before a config reload sets hub_key_raw). */
  bool raw_set = false;
  for (int i = 0; i < HUB_KEY_RAW_LEN; i++) {
    if (state->hub_key_raw[i]) { raw_set = true; break; }
  }
  if (raw_set) {
    memcpy(ed_priv, state->hub_key_raw,      32);
    memcpy(x_priv,  state->hub_key_raw + 32, 32);
    return true;
  }
  /* Fallback: first-run wizard path where config hasn't been saved yet. */
  int dec_len = 0;
  unsigned char *dec = base64_decode(state->hub_key, &dec_len);
  if (!dec || dec_len != HUB_KEY_RAW_LEN) {
    log_message(L_INFO, state, "[HUB] hub_key is not a valid 64-byte Curve25519 key\n");
    if (dec) { secure_wipe(dec, HUB_KEY_RAW_LEN); free(dec); }
    return false;
  }
  memcpy(ed_priv, dec,      32);
  memcpy(x_priv,  dec + 32, 32);
  /* Cache into hub_key_raw for subsequent calls. */
  memcpy(state->hub_key_raw, dec, HUB_KEY_RAW_LEN);
  secure_wipe(dec, HUB_KEY_RAW_LEN);
  free(dec);
  return true;
}

bool bot_self_pub_refresh(bot_state_t *state) {
  unsigned char priv[HUB_KEY_RAW_LEN];
  state->self_pub_set = false;
  memset(state->self_pub, 0, sizeof(state->self_pub));
  if (state->hub_key[0] == '\0') {
    bool raw_set = false;
    for (int i = 0; i < HUB_KEY_RAW_LEN; i++)
      if (state->hub_key_raw[i]) { raw_set = true; break; }
    if (!raw_set) return false;
  }
  if (!bot_key_decode(state, priv, priv + 32)) return false;
  state->self_pub_set = crypto_combined_pub_from_priv(priv, state->self_pub);
  secure_wipe(priv, sizeof(priv));
  return state->self_pub_set;
}

/* Encrypt one [cmd][len][payload] frame under the hub session key and send
 * it.  Returns false (after disconnecting on a send error) if it could not. */
static bool hub_send_frame(bot_state_t *state, int cmd, const char *payload,
                           int pay_len) {
  if (!state->hub_authenticated || state->hub_fd == -1) return false;
  if (pay_len < 0 || pay_len > MAX_BUFFER - 64) return false;
  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)cmd;
  uint32_t inner_len = htonl((uint32_t)pay_len);
  memcpy(&plain[1], &inner_len, 4);
  if (pay_len) memcpy(&plain[5], payload, (size_t)pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);
  secure_wipe(plain, (size_t)(5 + pay_len));
  if (cipher_len <= 0) return false;
  memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
  uint32_t net_len = htonl((uint32_t)(cipher_len + GCM_TAG_LEN));
  memcpy(cipher, &net_len, 4);
  int total = 4 + cipher_len + GCM_TAG_LEN;
  if (send(state->hub_fd, cipher, total, 0) != total) {
    hub_client_disconnect(state);
    return false;
  }
  return true;
}

/* Sign a domain-separated challenge with the Ed25519 private key.
 * msg = "irchub-bot-challenge-v1|UUID|" + hub_eph_pub(32) + challenge(32)
 * sig_out is 64 bytes. */
static bool ed25519_sign_challenge(bot_state_t *state,
                                   const unsigned char *challenge,
                                   const unsigned char *hub_eph_pub,
                                   unsigned char sig_out[64]) {
  unsigned char ed_priv[32], x_priv[32];
  if (!bot_key_decode(state, ed_priv, x_priv)) return false;
  secure_wipe(x_priv, 32);

  EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ed_priv, 32);
  secure_wipe(ed_priv, 32);
  if (!pk) {
    log_message(L_INFO, state, "[HUB] Failed to load Ed25519 private key\n");
    return false;
  }

  /* Build: "irchub-bot-challenge-v1|UUID|" + hub_eph_pub(32) + challenge(32) */
  size_t uuid_len = strlen(state->bot_uuid);
  size_t prefix_len = 24 + uuid_len + 1;  /* "irchub-bot-challenge-v1|" + uuid + "|" */
  size_t msg_len = prefix_len + 32 + 32;
  unsigned char *msg = malloc(msg_len);
  if (!msg) {
    EVP_PKEY_free(pk);
    log_message(L_INFO, state, "[HUB] OOM building challenge transcript\n");
    return false;
  }
  size_t off = 0;
  memcpy(msg + off, "irchub-bot-challenge-v1|", 24); off += 24;
  memcpy(msg + off, state->bot_uuid, uuid_len);       off += uuid_len;
  msg[off++] = '|';
  memcpy(msg + off, hub_eph_pub, 32);                 off += 32;
  memcpy(msg + off, challenge, 32);                   off += 32;

  EVP_MD_CTX *md = EVP_MD_CTX_new();
  bool ok = false;
  size_t siglen = 64;
  if (md && EVP_DigestSignInit(md, NULL, NULL, NULL, pk) == 1
         && EVP_DigestSign(md, sig_out, &siglen, msg, msg_len) == 1
         && siglen == 64)
    ok = true;
  if (md) EVP_MD_CTX_free(md);
  EVP_PKEY_free(pk);
  secure_wipe(msg, msg_len);
  free(msg);
  if (!ok) log_message(L_INFO, state, "[HUB] Ed25519 signing failed\n");
  return ok;
}

// Derive session key: X25519(bot_x_priv, hub_eph_pub) → HKDF → session_key
static bool x25519_derive_session_key(bot_state_t *state,
                                      const unsigned char hub_eph_pub[32],
                                      const unsigned char challenge[32],
                                      unsigned char session_key_out[32]) {
  unsigned char ed_priv[32], x_priv[32];
  if (!bot_key_decode(state, ed_priv, x_priv)) return false;
  secure_wipe(ed_priv, 32);

  // X25519 ECDH (rejects a low-order hub_eph_pub)
  unsigned char shared[32];
  bool ok = crypto_x25519_derive(x_priv, hub_eph_pub, shared);
  secure_wipe(x_priv, 32);
  if (!ok) {
    log_message(L_INFO, state, "[HUB] X25519 derive failed\n");
    return false;
  }

  // HKDF-SHA256: ikm=shared, salt=challenge, info="irchub-bot-session-v1|UUID"
  unsigned char info[96];
  int info_len = snprintf((char *)info, sizeof(info),
                          "irchub-bot-session-v1|%s", state->bot_uuid);
  int rc = crypto_hkdf_sha256(shared, 32, challenge, 32,
                               info, (size_t)info_len,
                               session_key_out, 32);
  secure_wipe(shared, 32);
  if (rc != 0) {
    log_message(L_INFO, state, "[HUB] HKDF failed\n");
    return false;
  }
  return true;
}

void hub_client_disconnect(bot_state_t *state) {
  if (state->hub_fd != -1) {
    shutdown(state->hub_fd, SHUT_RDWR);
    close(state->hub_fd);
    state->hub_fd = -1;
  }
  state->hub_connected = false;
  state->hub_authenticated = false;
  state->hub_connecting = false;
  state->hub_connect_time = 0;
  auth_state = HUB_AUTH_NONE;
  secure_wipe(state->hub_session_key, 32);
  state->current_hub[0] = '\0'; // Clear current hub tracking
  state->last_hub_connect_attempt = time(NULL);
  last_pong_sent = 0;
  /* The tree came from the hub we just lost; keep the rows so 'bots' can
   * still answer, but clear the presence we believe the hub holds so the next
   * authentication re-reports unconditionally. */
  state->presence_server[0] = '\0';
  state->last_presence_sent = 0;
}

void hub_client_heartbeat(bot_state_t *state) {
  if (state->hub_count == 0 || !state->hub_connected ||
      !state->hub_authenticated || state->hub_fd == -1)
    return;
  time_t now = time(NULL);
  /* Presence is cheap and self-throttling, so it rides the same tick as the
   * keepalive rather than needing a timer of its own. */
  hub_client_send_presence(state, false);
  if (now - state->last_hub_ping_time < 30)
    return;
  state->last_hub_ping_time = now;
  unsigned char plain[16] = {0}, buffer[128] = {0}, tag[GCM_TAG_LEN] = {0};
  plain[0] = (unsigned char)CMD_PING;
  uint32_t zero = 0;
  memcpy(&plain[1], &zero, 4);
  int enc_len =
      crypto_aes_gcm_encrypt(plain, 5, state->hub_session_key, buffer + 4, tag);
  if (enc_len > 0) {
    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
    memcpy(buffer, &net_len, 4);
    if (send(state->hub_fd, buffer, 4 + enc_len + GCM_TAG_LEN, 0) !=
        (ssize_t)(4 + enc_len + GCM_TAG_LEN)) {
      hub_client_disconnect(state);
    }
  }
}

void hub_client_sync_hostmask(bot_state_t *state) {
  if (state->actual_hostname[0] == '\0') return;
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) return;
  log_message(L_DEBUG, state, "[DEBUG] Syncing hostmask via delta: %s\n",
              state->actual_hostname);
  hub_client_push_delta(state, "h", state->actual_hostname,
                        state->actual_hostname_ts);
}

/* Tell the hub what we are running: version, the IRC server we are actually
 * on, and when this process started.  Volatile on both sides -- it feeds the
 * 'bots' tree and nothing else, and is never written to either config.
 *
 * Sent when it changes (a jump to another server, a reconnect) and refreshed
 * on a slow timer so a hub that restarted relearns us without waiting for the
 * bot to do anything.  force re-sends even when nothing changed. */
void hub_client_send_presence(bot_state_t *state, bool force) {
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) return;

  /* Prefer the server name the link actually reported over the configured
   * entry: after a redirect they differ, and the tree should show the truth. */
  char server[TREE_SERVER_MAX + 1] = "";
  if (state->status & S_CONNECTED) {
    const char *cfg = (state->current_server_index >= 0 &&
                       state->current_server_index < state->server_count)
                          ? state->server_list[state->current_server_index]
                          : NULL;
    /* Explicit precision: a server name longer than the presence field is
     * truncated on purpose, not an oversight. */
    if (state->actual_server_name[0])
      snprintf(server, sizeof(server), "%.*s", (int)sizeof(server) - 1,
               state->actual_server_name);
    else if (cfg)
      snprintf(server, sizeof(server), "%.*s", (int)sizeof(server) - 1, cfg);
  }

  time_t now = time(NULL);
  bool changed = strcmp(server, state->presence_server) != 0;
  if (!force && !changed && state->last_presence_sent &&
      now - state->last_presence_sent < BOT_PRESENCE_REPORT_INTERVAL)
    return;

  /* The variant rides last: a hub that predates it reads the start time
   * with atoll(), which stops at the '|', so older hubs are unaffected. */
  char payload[TREE_VERSION_MAX + TREE_SERVER_MAX + TREE_VARIANT_MAX + 64];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s|%lld|%s",
                         BOT_VERSION, server, (long long)state->bot_start_time,
                         BOT_UPDATE_VARIANT);
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload)) return;

  if (hub_send_frame(state, CMD_BOT_PRESENCE, payload, pay_len)) {
    snprintf(state->presence_server, sizeof(state->presence_server), "%s",
             server);
    state->last_presence_sent = now;
    if (changed)
      log_message(L_DEBUG, state, "[HUB] Presence: %s on %s\n", BOT_VERSION,
                  server[0] ? server : "(no server)");
  }
}

/* ---- Network upgrade (hub-orchestrated rolling upgrade) ------------------
 * The bot is a follower here.  It answers CMD_UPGRADE_PREPARE with what it is
 * and whether it could take the target build, touches nothing until
 * CMD_UPGRADE_COMMIT names the same upgrade, and restores the retained build
 * on CMD_UPGRADE_ABORT.  None of this is reachable from IRC or DCC: the
 * frames only arrive on the authenticated hub link, which is the whole point
 * of the standalone-only gate on the 'update' command. */

/* Copy src into a '|'-free, control-byte-free field.  Reasons carry text that
 * originated in a manifest, and the wire format splits on '|'. */
static void upgrade_field(char *dst, size_t dst_size, const char *src) {
  if (!dst || dst_size == 0) return;
  size_t o = 0;
  for (const char *p = src ? src : ""; *p && o + 1 < dst_size; p++) {
    unsigned char c = (unsigned char)*p;
    if (c == '|') c = '/';
    if (c < 0x20 || c == 0x7f) c = ' ';
    dst[o++] = (char)c;
  }
  dst[o] = '\0';
}

/* id|uuid|cur_ver|variant|arch|libc|ready|reason */
static void hub_client_send_upgrade_ready(bot_state_t *state, const char *id,
                                          bool ready, const char *reason) {
  char arch[32], libc[16], clean_reason[192];
  updater_host_arch(arch, sizeof(arch));
  updater_host_libc(libc, sizeof(libc));
  upgrade_field(clean_reason, sizeof(clean_reason), reason);

  char payload[MAX_BUFFER / 8];
  int n = snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s|%s|%d|%s", id,
                   state->bot_uuid, BOT_VERSION, updater_host_variant(), arch,
                   libc, ready ? 1 : 0, clean_reason);
  if (n <= 0 || n >= (int)sizeof(payload)) return;
  hub_send_frame(state, CMD_UPGRADE_READY, payload, n);
  log_message(L_INFO, state, "[UPGRADE] %s upgrade %s%s%s\n",
              ready ? "Ready for" : "Cannot take", id,
              clean_reason[0] ? ": " : "", clean_reason);
}

/* id|uuid|status|new_ver */
void hub_client_send_upgrade_result(bot_state_t *state, const char *id,
                                    const char *status, const char *detail) {
  char clean_detail[192];
  upgrade_field(clean_detail, sizeof(clean_detail), detail);
  char payload[MAX_BUFFER / 8];
  int n = snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s", id,
                   state->bot_uuid, status, BOT_VERSION, clean_detail);
  if (n <= 0 || n >= (int)sizeof(payload)) return;
  hub_send_frame(state, CMD_UPGRADE_RESULT, payload, n);
}

/* Called once per authenticated link.  If this process is the product of a
 * hub-driven upgrade, the marker left behind by updater_hub_commit() says
 * which run it belongs to; report whether we came up on the version that run
 * was aiming at.  The hub also infers success from the presence frame, so a
 * lost RESULT costs nothing. */
void hub_client_report_upgrade_result(bot_state_t *state) {
  char id[64], want[64];
  if (!updater_take_pending_upgrade(id, sizeof(id), want, sizeof(want))) return;
  bool ok = (updater_version_cmp(BOT_VERSION, want) == 0);
  snprintf(state->upgrade_installed_id, sizeof(state->upgrade_installed_id),
           "%s", id);
  log_message(L_INFO, state, "[UPGRADE] Restarted after %s: running %s (wanted %s)\n",
              id, BOT_VERSION, want);
  hub_client_send_upgrade_result(state, id, ok ? "ok" : "version-mismatch",
                                 ok ? "" : want);
}

/* id|target_ver|variant|kind|min_from|manifest_base — the hub is asking
 * whether we could move to target_ver.  Answer only; nothing is downloaded
 * and nothing on disk is touched until COMMIT. */
/* ==========================================================================
 * '|'-delimited wire fields
 *
 * sscanf's "%[^|]" cannot match an EMPTY field: the conversion fails there
 * and every field after it is left untouched.  An UPGRADE_PREPARE that names
 * neither a variant nor an artifact kind — "id|2.99.0|||*|file://…" — was
 * therefore read as two fields, silently dropping the manifest base and
 * sending the updater back to the compiled-in release URL.  These are the C
 * counterpart of split('|') in ircbot.rs, so both builds read a frame the
 * same way.
 * ========================================================================== */

/* Field `idx` of `s`, NUL-terminated into `dst`.  An over-long field is a
 * malformed frame, not something to truncate silently: false, `dst` empty. */
static bool wire_field(const char *s, int idx, char *dst, size_t cap) {
  if (!dst || cap == 0) return false;
  dst[0] = '\0';
  if (!s) return false;
  for (int i = 0; i < idx; i++) {
    const char *bar = strchr(s, '|');
    if (!bar) return false;
    s = bar + 1;
  }
  const char *bar = strchr(s, '|');
  size_t len = bar ? (size_t)(bar - s) : strcspn(s, "\r\n");
  if (len >= cap) return false;
  memcpy(dst, s, len);
  dst[len] = '\0';
  return true;
}

/* Field `idx` and everything after it, minus any trailing CR/LF: the last
 * field of a frame is free text and may itself contain '|'.  Display text is
 * clamped to the buffer rather than rejected. */
static bool wire_tail(const char *s, int idx, char *dst, size_t cap) {
  if (!dst || cap == 0) return false;
  dst[0] = '\0';
  if (!s) return false;
  for (int i = 0; i < idx; i++) {
    const char *bar = strchr(s, '|');
    if (!bar) return false;
    s = bar + 1;
  }
  size_t len = strcspn(s, "\r\n");
  if (len >= cap) len = cap - 1;
  memcpy(dst, s, len);
  dst[len] = '\0';
  return true;
}

static void hub_client_handle_upgrade_prepare(bot_state_t *state,
                                              const char *payload) {
  char id[64] = "", ver[64] = "", variant[8] = "", kind[8] = "";
  char min_from[64] = "", base[512] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ver, sizeof(ver)) || !id[0] || !ver[0]) {
    log_message(L_INFO, state, "[UPGRADE] Malformed UPGRADE_PREPARE\n");
    return;
  }
  wire_field(payload, 2, variant, sizeof(variant));
  wire_field(payload, 3, kind, sizeof(kind));
  wire_field(payload, 4, min_from, sizeof(min_from));
  /* A bounded field, not the tail: a hub's peer-facing PREPARE appends the
   * hubs' own target and base after it, and those are not the bot's. */
  wire_field(payload, 5, base, sizeof(base));

  const char *reason = "";
  bool ready = true;
  if (updater_version_cmp(ver, BOT_VERSION) == 0) {
    ready = false;
    reason = "already running the target version";
  } else if (updater_version_cmp(ver, BOT_VERSION) < 0) {
    ready = false;
    reason = "target is older than the running version";
  } else if (min_from[0] && strcmp(min_from, "*") != 0 &&
             updater_version_cmp(BOT_VERSION, min_from) < 0) {
    /* The hub walks the intermediate releases when it sees this. */
    ready = false;
    reason = "running version is below the target's min_from";
  } else if (access(PASS_FILE, R_OK) != 0) {
    /* Without the machine-bound password file the replacement binary would
     * stop at a password prompt with nobody to answer it. */
    ready = false;
    reason = "no " PASS_FILE "; cannot restart unattended";
  } else if (state->executable_path[0] != '/') {
    ready = false;
    reason = "executable path is not absolute";
  }

  if (ready) {
    /* Remember the plan: COMMIT repeats only the id and the version. */
    snprintf(state->upgrade_id, sizeof(state->upgrade_id), "%s", id);
    snprintf(state->upgrade_target, sizeof(state->upgrade_target), "%s", ver);
    snprintf(state->upgrade_variant, sizeof(state->upgrade_variant), "%s",
             variant[0] ? variant : updater_host_variant());
    snprintf(state->upgrade_base, sizeof(state->upgrade_base), "%s", base);
    state->upgrade_prepared = time(NULL);
  }
  (void)kind; /* the artifact kind is chosen from the manifest at COMMIT */
  hub_client_send_upgrade_ready(state, id, ready, reason);
}

/* id|target_ver|variant — go.  Only an id we acknowledged at PREPARE, and
 * only while that acknowledgement is still fresh, may commit. */
static void hub_client_handle_upgrade_commit(bot_state_t *state,
                                             const char *payload) {
  char id[64] = "", ver[64] = "", variant[8] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ver, sizeof(ver)) || !id[0] || !ver[0]) {
    log_message(L_INFO, state, "[UPGRADE] Malformed UPGRADE_COMMIT\n");
    return;
  }
  wire_field(payload, 2, variant, sizeof(variant));
  if (!state->upgrade_id[0] || strcmp(state->upgrade_id, id) != 0) {
    hub_client_send_upgrade_result(state, id, "fail",
                                   "no matching UPGRADE_PREPARE");
    return;
  }
  if (strcmp(state->upgrade_target, ver) != 0) {
    hub_client_send_upgrade_result(state, id, "fail",
                                   "commit version differs from prepare");
    return;
  }
  if (time(NULL) - state->upgrade_prepared > UPGRADE_PREPARE_TTL) {
    state->upgrade_id[0] = '\0';
    hub_client_send_upgrade_result(state, id, "fail", "prepare expired");
    return;
  }

  const char *err = NULL;
  if (!updater_hub_commit(state, id, ver,
                          variant[0] ? variant : state->upgrade_variant,
                          state->upgrade_base, &err)) {
    /* Nothing was changed on disk; stay on this build and say why. */
    log_message(L_INFO, state, "[UPGRADE] Commit %s refused: %s\n", id,
                err ? err : "unknown error");
    hub_client_send_upgrade_result(state, id, "fail", err ? err : "failed");
    state->upgrade_id[0] = '\0';
  }
  /* On success updater_hub_commit() does not return: the process is replaced
   * and hub_client_report_upgrade_result() reports in after the restart. */
}

/* id|reason — put the retained build back.  By the time this arrives the new
 * binary is usually already the running process, so undoing it is another
 * exec; a bot that has nothing retained just says so. */
static void hub_client_handle_upgrade_abort(bot_state_t *state,
                                            const char *payload) {
  char id[64] = "", reason[192] = "";
  wire_field(payload, 0, id, sizeof(id));
  wire_tail(payload, 1, reason, sizeof(reason));
  log_message(L_INFO, state, "[UPGRADE] Abort %s: %s\n",
              id[0] ? id : "(no id)", reason[0] ? reason : "no reason given");
  state->upgrade_id[0] = '\0';
  state->upgrade_prepared = 0;
  /* Only the run that installed the build we are running may take it back.
   * A bot that refused the COMMIT (a bad hash, no .ircbot.pass) never moved,
   * and its <exe>.prev is the build from before an earlier, completed run:
   * rolling back to it would walk a healthy node off the version the rest of
   * the mesh is on. */
  if (!id[0] || strcmp(id, state->upgrade_installed_id) != 0) {
    log_message(L_INFO, state,
                "[UPGRADE] Abort %s: this bot is not running that run's build; "
                "nothing to roll back\n", id[0] ? id : "(no id)");
    hub_client_send_upgrade_result(state, id[0] ? id : "-", "aborted",
                                   "not moved by this run");
    return;
  }
  if (!updater_hub_rollback(state, reason[0] ? reason : "hub aborted the upgrade"))
    hub_client_send_upgrade_result(state, id[0] ? id : "-", "aborted",
                                   "nothing retained to roll back to");
  /* A successful rollback execs; the hub sees the old version reappear. */
}

/* Ingest a CMD_BOT_TREE push.  Every field is hub-supplied text that ends up
 * in an admin's IRC client, so each one is length-capped and stripped of
 * control bytes here rather than at render time.  A malformed row is skipped,
 * never partially applied. */
static void hub_client_process_tree(bot_state_t *state, char *payload,
                                    int payload_len) {
  if (!payload || payload_len <= 0) return;
  payload[payload_len] = '\0';

  int count = 0;
  char *saveptr = NULL;
  for (char *line = strtok_r(payload, "\n", &saveptr);
       line && count < MAX_BOT_TREE_ROWS;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '\0' || line[1] != '|') continue;

    /* Split on '|' in place: the hub strips '|' from every value it forwards,
     * so a fixed field count is unambiguous. */
    char *f[8] = {0};
    int n = 0;
    char *cur = line + 2;
    while (n < 8) {
      f[n++] = cur;
      char *sep = strchr(cur, '|');
      if (!sep) break;
      *sep = '\0';
      cur = sep + 1;
    }

    bot_tree_row_t row;
    memset(&row, 0, sizeof(row));
    row.kind = (char)tolower((unsigned char)line[0]);

    if (row.kind == 'h' && n >= 5) {
      row.depth = atoi(f[0]);
      snprintf(row.name, sizeof(row.name), "%s", f[1]);
      snprintf(row.uuid, sizeof(row.uuid), "%s", f[2]);
      row.online = (atoi(f[3]) != 0);
      row.uptime = (time_t)atoll(f[4]);
      /* Version is the newest field on this row; a hub that does not send it
       * simply leaves the column blank. */
      if (n >= 6 && strcmp(f[5], "-") != 0)
        snprintf(row.version, sizeof(row.version), "%s", f[5]);
      /* The code base (c / rs) came after it; same rule, blank if absent. */
      if (n >= 7 && strcmp(f[6], "-") != 0)
        snprintf(row.variant, sizeof(row.variant), "%s", f[6]);
    } else if (row.kind == 'b' && n >= 6) {
      row.depth = atoi(f[0]);
      snprintf(row.name, sizeof(row.name), "%s", f[1]);
      snprintf(row.uuid, sizeof(row.uuid), "%s", f[2]);
      if (strcmp(f[3], "-") != 0)
        snprintf(row.version, sizeof(row.version), "%s", f[3]);
      if (strcmp(f[4], "-") != 0)
        snprintf(row.server, sizeof(row.server), "%s", f[4]);
      row.uptime = (time_t)atoll(f[5]);
      if (n >= 7 && strcmp(f[6], "-") != 0)
        snprintf(row.variant, sizeof(row.variant), "%s", f[6]);
      row.online = true;
    } else if (row.kind == 'd' && n >= 3) {
      snprintf(row.name, sizeof(row.name), "%s", f[0]);
      snprintf(row.uuid, sizeof(row.uuid), "%s", f[1]);
      row.uptime = (time_t)atoll(f[2]); /* last seen, not a duration */
      row.online = false;
    } else {
      continue;
    }
    if (strcmp(row.name, "-") == 0) row.name[0] = '\0';
    if (row.depth < 0) row.depth = 0;
    if (row.depth > MAX_TREE_DEPTH) row.depth = MAX_TREE_DEPTH;
    state->bot_tree[count++] = row;
  }

  state->bot_tree_count = count;
  state->bot_tree_ts = time(NULL);
 /* This logs excessively without much use; commented out for now. log_message(L_DEBUG, state, "[HUB] Bot tree updated (%d rows)\n", count); */
}

/* Push a single key=value change to the hub via CMD_BOT_DELTA.
 * This is a targeted update that the hub fans out as one DELTA per peer,
 * instead of the full config push which fans out ~50 lines.  Falls back to
 * hub_client_push_config if ts == 0 or key is empty. */
bool hub_client_push_delta(bot_state_t *state, const char *key,
                           const char *value, time_t ts) {
  if (!key || key[0] == '\0') return false;
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) return false;

  char payload[MAX_BUFFER];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s|%ld",
                         key, value ? value : "", (long)(ts ? ts : time(NULL)));
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload)) return false;

  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_BOT_DELTA;
  uint32_t inner_len = htonl(pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      log_message(L_DEBUG, state, "[HUB] Delta pushed: %s=%s ts=%ld\n",
                  key, value ? value : "", (long)ts);
      return true;
    } else {
      log_message(L_INFO, state, "[HUB] Delta push failed, falling back\n");
      hub_client_disconnect(state);
      return false;
    }
  }
  return false;
}

/**
 * Generate config payload for hub sync
 * Includes: c| (channels), h| (hostmask), n| (nick), v| (protocol version)
 * Excludes: a|, o|, m| (hub-authoritative; pushed separately by
 * hub_client_push_admin_delta) and the local-only s|, u|, g|, l|, i|, k|
 * Under opt 'h' (OPT_HUB_ONLY_MUTATIONS) c| is omitted as well: the bot
 * refuses join/part locally, so those records can only be the hub's own copy,
 * and irchub's process_bot_config_push rejects them by type before any
 * timestamp compare — pushing them would just log one REJECTED line per
 * record on every connect.  (The retired bot password p| is never sent.)
 */
void hub_client_generate_config_payload(bot_state_t *state, char *buffer,
                                        int max_len) {
  int offset = 0;
  int written;
  const bool hub_only = is_opt_set(state, OPT_HUB_ONLY_MUTATIONS);

  // Channels
  if (!hub_only) {
    for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
      const char *op = c->is_managed ? "add" : "del";
      log_message(L_DEBUG, state, "[HUB-PUSH] Channel %s: is_managed=%d op=%s ts=%ld\n",
                  c->name, c->is_managed, op, (long)c->timestamp);
      if (c->key[0] != '\0') {
        written = snprintf(buffer + offset, max_len - offset,
                           "c|%s|%s|%d|%s|%ld\n",
                           c->name, c->key, (int)c->modes, op,
                           (long)c->timestamp);
      } else {
        written = snprintf(buffer + offset, max_len - offset,
                           "c|%s||%d|%s|%ld\n",
                           c->name, (int)c->modes, op,
                           (long)c->timestamp);
      }
      if (written < 0 || written >= max_len - offset)
        break;
      offset += written;
    }
  }

  /* Admin/oper/mask records are hub-authoritative — bots receive them from hub,
   * they do NOT push them back. IRC admin commands (+admin, +usermask, etc.)
   * update local state and call hub_client_push_config, but only the bot-local
   * fields (channels, nick, hostmask) are included in the push payload.
   * The hub manages a|/o|/m| records via CMD_ADMIN_* commands only. */

  /* Protocol capability (passwordless.md §3.4), sent on every push and under
   * every opt.  The hub records it on this connection only (a downgraded
   * binary on the next connect is never mistaken for v2), answers the first
   * v >= 2 with a fresh config in the new a|/o|/b| shapes, and until then
   * sends legacy shapes with an empty password slot, which this bot also
   * parses.  (Bot->hub push namespace — unrelated to the v| vhost line in the
   * local config file.)  The timestamp field is unused. */
  written = snprintf(buffer + offset, max_len - offset, "v|%d|%d\n",
                     BOT_PROTO_VERSION, 1);
  if (written > 0 && written < max_len - offset) {
    offset += written;
  }

  // Hostmask — use the timestamp captured when actual_hostname last changed;
  // never use time(NULL) here or every push looks like new data to the hub.
  if (state->actual_hostname[0] != '\0' && state->actual_hostname_ts > 0) {
    written = snprintf(buffer + offset, max_len - offset, "h|%s|%ld\n",
                       state->actual_hostname, (long)state->actual_hostname_ts);
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
  }

  // Nick — same stable-timestamp rule.
  if (state->current_nick[0] != '\0' && state->current_nick_ts > 0) {
    written = snprintf(buffer + offset, max_len - offset, "n|%s|%ld\n",
                       state->current_nick, (long)state->current_nick_ts);
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
  }

  buffer[offset] = '\0';
}

/**
 * Send an op request via hub to another bot
 * Returns true if request was sent via hub, false to fallback to PRIVMSG
 */
bool hub_client_request_op(bot_state_t *state, const char *target_uuid,
                           const char *channel) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1) {
    return false; // Hub not available, use PRIVMSG fallback
  }

  // Don't request from ourselves
  if (strcmp(target_uuid, state->bot_uuid) == 0) {
    return false;
  }

  // Build payload: target_uuid|channel
  char payload[256];
  snprintf(payload, sizeof(payload), "%s|%s", target_uuid, channel);

  log_message(L_INFO, state,
              "[HUB] Requesting ops via hub: target=%s chan=%s\n", target_uuid,
              channel);

  int pay_len = strlen(payload);
  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_OP_REQUEST;
  uint32_t inner_len = htonl(pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      return true;
    }
    hub_client_disconnect(state);
  }

  return false;
}

/* Route a sealed bot command ("~B2 <b64>") to a specific bot by UUID via hub
 * relay.  The hub forwards it opaquely as "<sender_uuid>|~B2 <b64>".
 * Returns true if the frame was sent to the hub; false to fall back to PRIVMSG. */
bool hub_client_relay_bot_command(bot_state_t *state, const char *target_uuid,
                                  const char *frame_line) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1)
    return false;

  char payload[MAX_BUFFER];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s",
                         target_uuid, frame_line);
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload)) return false;
  if (!hub_send_frame(state, CMD_BOT_RELAY, payload, pay_len)) return false;
  log_message(L_DEBUG, state,
              "[BOT-COMM] CMD_BOT_RELAY sent to hub for %s\n", target_uuid);
  return true;
}

/* Send CMD_INVITE_REQUEST to hub: hub will broadcast to all bots */
bool hub_client_send_invite_request(bot_state_t *state, const char *nick,
                                    const char *channel) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1)
    return false;

  char payload[256];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s", nick, channel);
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload))
    return false;

  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_INVITE_REQUEST;
  uint32_t inner_len = htonl(pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      log_message(L_INFO, state,
                  "[HUB] Sent INVITE_REQUEST for %s in %s\n", nick, channel);
      return true;
    }
    hub_client_disconnect(state);
  }
  return false;
}

/* Ask the mesh to let us into a channel.  Only `kind|channel` goes on the
 * wire: the hub resolves our nick and hostmask from its own records, so this
 * frame cannot be used to ask for someone else's mask to be unbanned. */
bool hub_client_send_chan_request(bot_state_t *state, const char *kind,
                                  const char *channel) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1)
    return false;

  char payload[MAX_CHAN + 16];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s", kind, channel);
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload))
    return false;
  if (!hub_send_frame(state, CMD_CHAN_REQUEST, payload, pay_len))
    return false;

  log_message(L_INFO, state, "[CHANREQ] Sent %s request for %s to hub\n", kind,
              channel);
  return true;
}

/* Answer one -- today only a `key`.  `data` carries the key, so the buffer is
 * wiped before returning rather than being left on the stack. */
bool hub_client_send_chan_reply(bot_state_t *state, const char *request_id,
                                const char *kind, const char *channel,
                                const char *status, const char *data) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1)
    return false;

  char payload[MAX_CHAN + MAX_KEY + 96];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s", request_id,
                         kind, channel, status, data ? data : "");
  bool ok = false;
  if (pay_len > 0 && pay_len < (int)sizeof(payload))
    ok = hub_send_frame(state, CMD_CHAN_REPLY, payload, pay_len);
  secure_wipe(payload, sizeof(payload));
  return ok;
}

// Alias for promoting local config to hub (e.g. on connect)
void hub_client_promote_local_config(bot_state_t *state) {
  hub_client_push_config(state);
}

/* Push all user/mask records to hub via CMD_CONFIG_PUSH so the hub can store
 * and broadcast newly created or modified admin/oper/mask records.  The hub's
 * process_bot_config_push uses strict ts > stored_ts, so unchanged records
 * (same timestamp) are silently rejected — only new or modified ones land. */
void hub_client_push_admin_delta(bot_state_t *state) {
  if (!state->hub_authenticated || state->hub_fd == -1) {
    /* No hub link: send it after the next authentication (see
     * admin_delta_pending).  The flag is saved at once, so a restart before
     * then still pushes: the records carry their newer timestamps, and the
     * hub's LWW keeps whichever side changed last. */
    if (state->hub_count > 0 && !state->admin_delta_pending) {
      state->admin_delta_pending = true;
      config_write_local_with_state_pass(state);
    }
    return;
  }
  /* Cleared once every frame went out; either way the debounced flush saves
   * the flag's new value. */
  state->admin_delta_pending = true;
  state->config_dirty = true;

  /* Every record goes out: when the lines exceed one frame they are split
   * across several CMD_CONFIG_PUSH frames at line boundaries (the hub applies
   * each line independently, LWW by timestamp).  Users precede masks so a new
   * user always lands before its first mask. */
  const int chunk_cap = MAX_BUFFER - 64;
  char payload[MAX_BUFFER];
  int offset = 0, frames = 0;
  int total_lines = state->user_record_count + state->mask_record_count;

  for (int i = 0; i < total_lines; i++) {
    char line[CFG_MASK_LINE_MAX > CFG_USER_LINE_MAX ? CFG_MASK_LINE_MAX
                                                    : CFG_USER_LINE_MAX];
    int w;
    if (i < state->user_record_count) {
      w = config_format_user_line(&state->user_records[i], line, sizeof(line));
    } else {
      const mask_record_t *m =
          &state->mask_records[i - state->user_record_count];
      w = snprintf(line, sizeof(line), "m|%s|%s|%s|%ld|%ld\n", m->uuid,
                   m->mask, m->is_active ? "add" : "del", (long)m->last_used,
                   (long)m->timestamp);
    }
    if (w <= 0 || w >= (int)sizeof(line)) {
      log_message(L_INFO, state, "[HUB] Admin delta: record %d too long; "
                                 "skipped\n", i);
      continue;
    }
    if (offset + w > chunk_cap) {
      if (!hub_send_frame(state, CMD_CONFIG_PUSH, payload, offset)) return;
      frames++;
      offset = 0;
    }
    memcpy(payload + offset, line, (size_t)w);
    offset += w;
  }
  if (offset > 0) {
    if (!hub_send_frame(state, CMD_CONFIG_PUSH, payload, offset)) return;
    frames++;
  }
  state->admin_delta_pending = false;
  if (frames > 0)
    log_message(L_INFO, state,
                "[HUB] Admin delta pushed (%d user, %d mask records, %d "
                "frame%s)\n", state->user_record_count,
                state->mask_record_count, frames, frames == 1 ? "" : "s");
}

/**
 * Push full config to hub
 * Called: After authentication, after config changes
 */
void hub_client_push_config(bot_state_t *state) {
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) {
    log_message(L_DEBUG, state, "[HUB-PUSH] Skipped push: hub_count=%d hub_fd=%d auth=%d\n",
                state->hub_count, state->hub_fd, state->hub_authenticated);
    return; // Not hub-managed or not connected
  }

  char payload[MAX_BUFFER];
  hub_client_generate_config_payload(state, payload, sizeof(payload));

  if (strlen(payload) == 0) {
    log_message(L_DEBUG, state, "[HUB] No config to push\n");
    return;
  }

  log_message(L_DEBUG, state, "[HUB-SYNC] Pushing config to hub (%zu bytes)\n",
              strlen(payload));

  int pay_len = strlen(payload);
  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_CONFIG_PUSH;
  uint32_t inner_len = htonl(pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
    memcpy(cipher, &net_len, 4);

    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      log_message(L_INFO, state, "[HUB] Config pushed to hub\n");
    } else {
      log_message(L_INFO, state, "[HUB] Failed to push config\n");
      hub_client_disconnect(state);
    }
  }
}

/* Push a single channel entry to hub after a live MODE change */
void hub_client_push_channel(bot_state_t *state, chan_t *chan) {
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated)
    return;

  const char *op = chan->is_managed ? "add" : "del";
  char payload[MAX_BUFFER];
  int pay_len;

  if (chan->key[0] != '\0') {
    pay_len = snprintf(payload, sizeof(payload), "c|%s|%s|%d|%s|%ld\n",
                       chan->name, chan->key, (int)chan->modes, op,
                       (long)chan->timestamp);
  } else {
    pay_len = snprintf(payload, sizeof(payload), "c|%s||%d|%s|%ld\n",
                       chan->name, (int)chan->modes, op,
                       (long)chan->timestamp);
  }

  if (pay_len <= 0 || pay_len >= (int)sizeof(payload))
    return;

  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_CONFIG_PUSH;
  uint32_t inner_len = htonl(pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      log_message(L_INFO, state, "[HUB] Pushed channel %s modes=%d to hub\n",
                  chan->name, (int)chan->modes);
    } else {
      log_message(L_INFO, state, "[HUB] Failed to push channel %s\n", chan->name);
      hub_client_disconnect(state);
    }
  }
}

/* PURGE|<cutoff>: drop tombstones (unmanaged channels, inactive user and
 * mask records) stamped before cutoff; 0 drops them all.  The hub sends it as
 * its own CMD_CONFIG_DATA frame after the purged full config.  Channel
 * tombstones are merged, not replaced, by a config push, so only this line
 * removes them.  Returns the number of entries dropped (saved when > 0). */
static int hub_client_apply_purge(bot_state_t *state, const char *arg) {
  char *end = NULL;
  errno = 0;
  long long cutoff_val = strtoll(arg, &end, 10);
  if (errno || end == arg || *end != '\0' || cutoff_val < 0) {
    log_message(L_INFO, state, "[HUB] Rejected malformed PURGE line\n");
    return 0;
  }
  time_t cutoff = (time_t)cutoff_val;
  int purged = 0;

  chan_t *c = state->chanlist;
  while (c) {
    chan_t *next = c->next;
    if (!c->is_managed && (cutoff == 0 || c->timestamp < cutoff)) {
      channel_remove(state, c->name);
      purged++;
    }
    c = next;
  }

  for (int i = 0; i < state->user_record_count; i++) {
    if (!state->user_records[i].is_active &&
        (cutoff == 0 || state->user_records[i].timestamp < cutoff)) {
      memmove(&state->user_records[i], &state->user_records[i + 1],
              (state->user_record_count - i - 1) * sizeof(user_record_t));
      state->user_record_count--;
      purged++;
      i--;
    }
  }

  for (int i = 0; i < state->mask_record_count; i++) {
    if (!state->mask_records[i].is_active &&
        (cutoff == 0 || state->mask_records[i].timestamp < cutoff)) {
      memmove(&state->mask_records[i], &state->mask_records[i + 1],
              (state->mask_record_count - i - 1) * sizeof(mask_record_t));
      state->mask_record_count--;
      purged++;
      i--;
    }
  }

  if (purged > 0) {
    log_message(L_INFO, state, "[HUB] Purged %d tombstoned entries\n", purged);
    config_write_with_state_pass(state);
  }
  return purged;
}

void hub_client_process_config_data(bot_state_t *state, const char *payload) {
  log_message(L_DEBUG, state, "[HUB-SYNC] Processing config data from hub\n");

  /* Hub is authoritative for user/mask records. Replace rather than merge so
   * the bot always has exactly the hub's current set — no stale or duplicate
   * UUIDs from a previous sync can accumulate. Preserve last_seen/last_used
   * that were updated locally since the last hub push.
   *
   * Only wipe a table when this payload actually carries records of that kind.
   * A payload legitimately lacking a|/o| (or m|) lines — the hub has none, or a
   * partial/other push — must NOT silently empty the in-memory table (which,
   * combined with the updates>0 save-gate below, would diverge RAM from disk).
   * When such lines ARE present the "replace to drop stale UUIDs" semantics
   * still hold, because parsing rebuilds the whole set. */
  bool has_user_lines = false, has_mask_lines = false, has_trust_set = false;
  for (const char *p = payload; p && *p; ) {
    if ((p[0] == 'a' || p[0] == 'o') && p[1] == '|') has_user_lines = true;
    else if (p[0] == 'm' && p[1] == '|') has_mask_lines = true;
    else if (p[0] == 'T' && p[1] == '|') has_trust_set = true;
    const char *nl = strchr(p, '\n');
    if (!nl) break;
    p = nl + 1;
  }

  user_record_t saved_users[MAX_USER_RECORDS];
  mask_record_t saved_masks[MAX_USER_MASKS];
  int saved_user_count = state->user_record_count;
  int saved_mask_count = state->mask_record_count;
  memcpy(saved_users, state->user_records, sizeof(user_record_t) * (size_t)saved_user_count);
  memcpy(saved_masks, state->mask_records, sizeof(mask_record_t) * (size_t)saved_mask_count);
  if (has_user_lines) state->user_record_count = 0;
  if (has_mask_lines) state->mask_record_count = 0;

  /* Change 5: static, sized to a full config payload so a large hub config is
   * parsed whole (no truncation).  Single-threaded, non-reentrant. */
  static char work_buf[MAX_CONFIG_PAYLOAD];
  snprintf(work_buf, sizeof(work_buf), "%s", payload);

  /* UUIDs named by this payload's b| lines.  With a T| marker the hub is
   * saying "this is the whole trusted set", and every other trusted bot is
   * dropped after the parse (a deleted or purged bot must lose ~B2 and op
   * trust).  Static like work_buf: single-threaded, non-reentrant. */
  static char listed_uuids[MAX_TRUSTED_BOTS][37];
  int listed_count = 0;

  char *saveptr;
  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;

  while (line) {
    if (strlen(line) < 2 || line[0] == '#') {
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    /* PURGE|<cutoff> is the one line whose type is a word, not a letter:
     * it has to be taken before the "X|" shape check below, which used to
     * drop it (bots never applied a hub purge). */
    if (strncmp(line, "PURGE|", 6) == 0) {
      hub_client_apply_purge(state, line + 6);
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    // Parse: type|field1|field2|operation|timestamp
    char type = line[0];
    if (line[1] != '|') {
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    char *data = line + 2; // Skip "type|"

    switch (type) {
    case 'c': // Channel
    {
      char chan[MAX_CHAN], key[MAX_KEY], op[8];
      long long ts;
      int parsed;
      int modes_val = 0;

      /* Try new 5-field format: chan|key|modes|op|ts */
      parsed = sscanf(data, "%64[^|]|%30[^|]|%d|%7[^|]|%lld",
                      chan, key, &modes_val, op, &ts);
      if (parsed < 5) {
        /* Try new 5-field without key: chan||modes|op|ts */
        modes_val = 0;
        parsed = sscanf(data, "%64[^|]||%d|%7[^|]|%lld",
                        chan, &modes_val, op, &ts);
        if (parsed >= 4) {
          key[0] = '\0';
        } else {
          /* Fall back to old 4-field: chan|key|op|ts */
          modes_val = 0;
          parsed = sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%lld",
                          chan, key, op, &ts);
          if (parsed < 3) {
            /* Old 4-field without key: chan||op|ts */
            parsed = sscanf(data, "%64[^|]||%7[^|]|%lld", chan, op, &ts);
            key[0] = '\0';
          }
        }
      }

      if (parsed >= 3) {
        bool is_add = (strcmp(op, "add") == 0);
        chan_t *c = channel_find(state, chan);

        log_message(L_DEBUG, state, "[HUB-SYNC] Channel %s: hub_ts=%lld local_ts=%ld op=%s\n",
                    chan, ts, c ? (long)c->timestamp : 0, op);

        if (!c && is_add) {
          // New channel from hub
          c = channel_add(state, chan);
          if (c) {
            if (key[0]) {
              size_t len = strlen(key);
              if (len >= MAX_KEY)
                len = MAX_KEY - 1;
              memcpy(c->key, key, len);
              c->key[len] = '\0';
            }
            c->modes = (chan_mode_t)modes_val;
            c->is_managed = true;
            c->timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Added channel: %s\n", chan);
          }
        } else if (c) {
          // Compare timestamps (a same-second del beats an add: lww_accepts)
          if (lww_accepts((time_t)ts, is_add, c->timestamp, c->is_managed)) {
            // Hub has newer data
            if (key[0]) {
              size_t len = strlen(key);
              if (len >= MAX_KEY)
                len = MAX_KEY - 1;
              memcpy(c->key, key, len);
              c->key[len] = '\0';
            }
            c->modes = (chan_mode_t)modes_val;
            bool was_managed = c->is_managed;
            c->is_managed = is_add;
            c->timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Updated channel: %s (%s)\n", chan,
                        op);
            // If channel changed from managed to unmanaged, PART the channel
            if (was_managed && !is_add && c->status == C_IN) {
              log_message(L_INFO, state, "[HUB] Parting channel %s (synced del)\n", chan);
              irc_printf(state, "PART %s :Hub sync\r\n", chan);
              c->status = C_OUT;
            }
            // If channel changed from unmanaged to managed, JOIN the channel
            if (!was_managed && is_add && c->status != C_IN) {
              log_message(L_INFO, state, "[HUB] Joining channel %s (synced add)\n", chan);
              if (c->key[0] != '\0') {
                irc_printf(state, "JOIN %s %s\r\n", chan, c->key);
              } else {
                irc_printf(state, "JOIN %s\r\n", chan);
              }
            }
          } else {
            log_message(L_DEBUG, state, "[HUB-SYNC] Rejected channel %s: hub_ts=%lld local_ts=%ld (not newer)\n",
                        chan, ts, (long)c->timestamp);
          }
        } else if (!c && !is_add) {
          log_message(L_DEBUG, state, "[HUB-SYNC] Skipped del for non-existent channel: %s\n", chan);
        }
      }
    } break;

    case 'm': // Usermask record (new: uuid|mask|add/del|last_used|ts)
    {
      char first_m[40] = {0};
      char *pfm = strchr(data, '|');
      if (pfm) { size_t fl=(size_t)(pfm-data); if(fl<sizeof(first_m)){memcpy(first_m,data,fl);first_m[fl]=0;} }
      bool is_new_m = (strlen(first_m)==36 && first_m[8]=='-' && first_m[13]=='-' && first_m[18]=='-' && first_m[23]=='-');
      if (is_new_m) {
        char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
        char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
        if (p1&&p2&&p3&&p4) {
          char uuid[37], mask_s[MAX_MASK_LEN], act[8];
          long long last_used, ts;
          snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(p1-data),data);
          snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(act,    sizeof(act),    "%.*s",(int)(p3-p2-1),p2+1);
          last_used = atoll(p3+1); ts = atoll(p4+1);
          bool is_active = (strncmp(act,"add",3)==0);
          mask_record_t *found_m = NULL;
          for (int mi=0; mi<state->mask_record_count; mi++) {
            if (strcmp(state->mask_records[mi].uuid,uuid)==0 &&
                strcasecmp(state->mask_records[mi].mask,mask_s)==0) {
              found_m = &state->mask_records[mi]; break;
            }
          }
          if (!found_m && state->mask_record_count < MAX_USER_MASKS) {
            found_m = &state->mask_records[state->mask_record_count++];
            memset(found_m,0,sizeof(*found_m));
            snprintf(found_m->uuid,sizeof(found_m->uuid),"%s",uuid);
            snprintf(found_m->mask,sizeof(found_m->mask),"%s",mask_s);
          }
          if (found_m && lww_accepts((time_t)ts, is_active, found_m->timestamp,
                                     found_m->is_active)) {
            found_m->is_active = is_active;
            if (last_used > found_m->last_used) found_m->last_used = last_used;
            found_m->timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Synced mask %s (%s)\n", mask_s, act);
          }
        }
      }
    } break;

    case 'o': // Oper user record  } config_parse_user_line: new, or legacy
    case 'a': // Admin user record }  (password slot dropped, key from field 7)
    {
      user_line_t ul;
      if (!config_parse_user_line(data, &ul)) {
        log_message(L_DEBUG, state, "[HUB-SYNC] Malformed %c| record ignored\n",
                    type);
        break;
      }
      user_record_t *found_u = NULL;
      for (int ui = 0; ui < state->user_record_count; ui++) {
        if (strcmp(state->user_records[ui].uuid, ul.uuid) == 0) {
          found_u = &state->user_records[ui]; break;
        }
      }
      if (!found_u && state->user_record_count < MAX_USER_RECORDS) {
        found_u = &state->user_records[state->user_record_count++];
        memset(found_u, 0, sizeof(*found_u));
        memcpy(found_u->uuid, ul.uuid, sizeof(found_u->uuid));
      }
      if (found_u && lww_accepts(ul.timestamp, ul.is_active,
                                 found_u->timestamp, found_u->is_active)) {
        memcpy(found_u->name, ul.name, sizeof(found_u->name));
        /* The hub is authoritative for the key too: a record that arrives
         * keyless leaves the user keyless (cannot authenticate). */
        memcpy(found_u->pubkey_b64, ul.pubkey_b64, sizeof(found_u->pubkey_b64));
        found_u->has_pubkey = ul.has_pubkey;
        found_u->type      = type;
        found_u->is_active = ul.is_active;
        if (ul.last_seen > found_u->last_seen) found_u->last_seen = ul.last_seen;
        found_u->timestamp = ul.timestamp;
        updates++;
        log_message(L_INFO, state, "[HUB] Synced user %s (%c/%s%s)\n", ul.name,
                    type, ul.is_active ? "add" : "del",
                    ul.has_pubkey ? "" : ", no key");
      }
    } break;

    case 'O': /* Network opt flags pushed by hub: O|<letters>|<ts> */
    {
      char flags[MAX_OPT_FLAGS + 1] = {0};
      long long ts = 0;
      /* The hub sends "O||<ts>" when every flag is cleared.  %[^|] fails on
       * an empty field, so parse that form on its own or a clear never lands
       * and the bot keeps enforcing e.g. opt 'h' after the network dropped it. */
      bool ok = (data[0] == '|')
                    ? (sscanf(data + 1, "%lld", &ts) == 1)
                    : (sscanf(data, "%32[^|]|%lld", flags, &ts) >= 1);
      if (ok) {
        char clean[MAX_OPT_FLAGS + 1];
        int w = 0;
        for (int i = 0; flags[i] && w < MAX_OPT_FLAGS; i++) {
          char c = flags[i];
          if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9'))
            clean[w++] = c;
        }
        clean[w] = '\0';
        if (opt_accepts((time_t)ts, clean, state->opt_flags_ts,
                        state->opt_flags)) {
          memcpy(state->opt_flags, clean, (size_t)w + 1);
          state->opt_flags_ts = (ts > 0) ? (time_t)ts : time(NULL);
          log_message(L_INFO, state, "[HUB-SYNC] opt flags updated -> '%s'\n",
                      state->opt_flags);
          updates++;
        }
      }
    } break;

    case 'p': // Retired bot password (pre-passwordless hub): ignored
      log_message(L_DEBUG, state, "[HUB-SYNC] Ignored retired p| line\n");
      break;

    case 'b': // Trusted bot: b|mask|uuid|pubkey|ts (legacy b|mask|uuid|ts)
    {
      trusted_bot_t in;
      if (!config_parse_bot_line(data, &in)) {
        /* A trust record is never stored truncated — a clipped mask or uuid
         * would silently mis-key every later match — so refuse instead. */
        log_message(L_INFO, state,
                    "[HUB] Rejected malformed/oversized trusted-bot line\n");
        break;
      }
      if (in.uuid[0] && listed_count < MAX_TRUSTED_BOTS)
        memcpy(listed_uuids[listed_count++], in.uuid, sizeof(listed_uuids[0]));

      // Find existing entry: prefer UUID match (handles nick/host changes),
      // fall back to hostmask match.  Also sweep out any duplicate entries
      // for the same UUID so stale masks from previous sessions don't linger.
      int existing_idx = -1;
      if (in.uuid[0] != '\0') {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          if (strcmp(state->trusted_bots[i].uuid, in.uuid) != 0) continue;
          if (existing_idx == -1) {
            existing_idx = i; // keep first match
          } else {
            memmove(&state->trusted_bots[i], &state->trusted_bots[i + 1],
                    (size_t)(state->trusted_bot_count - i - 1) *
                        sizeof(trusted_bot_t));
            state->trusted_bot_count--;
            i--;
          }
        }
      }
      if (existing_idx == -1) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          if (strcmp(state->trusted_bots[i].mask, in.mask) == 0) {
            existing_idx = i;
            break;
          }
        }
      }

      if (existing_idx != -1) {
        trusted_bot_t *ex = &state->trusted_bots[existing_idx];
        bool key_is_new = in.has_pub &&
            (!ex->has_pub || memcmp(ex->pub, in.pub, HUB_KEY_RAW_LEN) != 0);
        /* ts = max(hostmask ts, key ts) on the hub, so a rekey alone bumps it;
         * the equal-ts case covers a legacy-shaped line (no key) having been
         * applied first under the same hostmask ts. */
        if (in.ts > ex->ts || (in.ts == ex->ts && key_is_new)) {
          if (!in.has_pub && ex->has_pub && strcmp(ex->uuid, in.uuid) == 0) {
            /* Legacy-shaped line from a hub that has not seen our v|2 yet:
             * it carries no key — keep the one we have. */
            in.has_pub = true;
            memcpy(in.pub, ex->pub, HUB_KEY_RAW_LEN);
          }
          *ex = in;
          updates++;
          log_message(L_INFO, state, "[HUB] Updated trusted bot: %s%s\n",
                      in.mask, key_is_new ? " (new key)" : "");
        }
      } else if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
        state->trusted_bots[state->trusted_bot_count++] = in;
        updates++;
        log_message(L_INFO, state, "[HUB] Added trusted bot: %s%s\n", in.mask,
                    in.has_pub ? "" : " (no key yet)");
      }
    } break;

    case 'T': // T|<count>: end of the hub's complete trusted-bot list (swept below)
      break;

    default:
      log_message(L_DEBUG, state, "[HUB-SYNC] Unrecognized line type '%c': %s\n", type, line);
      break;
    }

    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (has_trust_set) {
    for (int i = 0; i < state->trusted_bot_count;) {
      const trusted_bot_t *tb = &state->trusted_bots[i];
      bool listed = false;
      for (int j = 0; j < listed_count && !listed; j++)
        listed = tb->uuid[0] && strcmp(listed_uuids[j], tb->uuid) == 0;
      if (listed) {
        i++;
        continue;
      }
      log_message(L_INFO, state,
                  "[HUB] Revoked trusted bot: %s (%s) - no longer registered "
                  "on the hub\n", tb->mask, tb->uuid[0] ? tb->uuid : "no uuid");
      memmove(&state->trusted_bots[i], &state->trusted_bots[i + 1],
              (size_t)(state->trusted_bot_count - i - 1) * sizeof(trusted_bot_t));
      state->trusted_bot_count--;
      memset(&state->trusted_bots[state->trusted_bot_count], 0,
             sizeof(trusted_bot_t));
      updates++;
    }
  }

  /* Restore locally-updated last_seen / last_used timestamps that are newer
   * than what the hub sent (e.g. from recent auths not yet flushed to hub). */
  for (int i = 0; i < state->user_record_count; i++) {
    user_record_t *u = &state->user_records[i];
    for (int j = 0; j < saved_user_count; j++) {
      if (strcmp(saved_users[j].uuid, u->uuid) == 0) {
        if (saved_users[j].last_seen > u->last_seen)
          u->last_seen = saved_users[j].last_seen;
        break;
      }
    }
  }
  for (int i = 0; i < state->mask_record_count; i++) {
    mask_record_t *m = &state->mask_records[i];
    for (int j = 0; j < saved_mask_count; j++) {
      if (strcmp(saved_masks[j].uuid, m->uuid) == 0 &&
          strcasecmp(saved_masks[j].mask, m->mask) == 0) {
        if (saved_masks[j].last_used > m->last_used)
          m->last_used = saved_masks[j].last_used;
        break;
      }
    }
  }

  if (updates > 0) {
    log_message(L_INFO, state, "[HUB] Applied %d config updates from hub\n",
                updates);
    /* Save locally only — do NOT push back to hub. Hub is authoritative for
     * a|/o|/m| records; echoing them back would create an infinite sync loop. */
    config_write_local_with_state_pass(state);
  } else {
    log_message(L_DEBUG, state, "[HUB-SYNC] No updates applied (all timestamps older or equal)\n");
  }
}

void hub_handle_response(bot_state_t *state, int cmd, char *payload,
                         int payload_len) {
  switch (cmd) {
  case CMD_PING:
    if (!HIDEPINGPONG)
      log_message(L_DEBUG, state, "[HUB] Received PING from hub\n");
    break;

  case CMD_BOT_TREE:
    hub_client_process_tree(state, payload, payload_len);
    break;

  case CMD_CONFIG_PULL:
    log_message(L_INFO, state, "[HUB] Hub requested config sync\n");
    break;

  case CMD_CONFIG_DATA:
    log_message(L_INFO, state, "[HUB] Received config from hub (%d bytes)\n",
                payload_len);
    if (payload && payload_len > 0) {
      hub_client_process_config_data(state, payload);
    }
    break;

  case CMD_UPDATE_PUBKEY:
    // Existing handler for hub-to-hub key updates (not used for bots)
    break;

  case CMD_BOT_KEY_UPDATE:
    /* v3: independent per-bot keys.  The bot's private key must never
     * arrive over the wire — reject any inbound "here's your new priv"
     * attempt from the hub.  Rekey is bot-local (see admin command 'rekey'). */
    log_message(L_INFO, state,
                "[HUB] Rejected CMD_BOT_KEY_UPDATE: per-bot independent keys; "
                "private keys do not cross the wire.\n");
    (void)payload; (void)payload_len;
    break;

  case CMD_OP_GRANT: {
    // Payload: requester_hostmask|channel
    // Example: bot3!~ident@47.217.20.145|#ircbot
    char hostmask[MAX_MASK_LEN];
    char channel[MAX_CHAN];

    if (sscanf(payload, "%255[^|]|%64s", hostmask, channel) == 2) {
      // Extract nick from hostmask (nick!user@host)
      char nick[MAX_NICK];
      char *bang = strchr(hostmask, '!');
      if (bang) {
        size_t nick_len = bang - hostmask;
        if (nick_len >= MAX_NICK)
          nick_len = MAX_NICK - 1;
        memcpy(nick, hostmask, nick_len);
        nick[nick_len] = '\0';
      } else {
        size_t nick_len = strlen(hostmask);
        if (nick_len >= sizeof(nick)) nick_len = sizeof(nick) - 1;
        memcpy(nick, hostmask, nick_len);
        nick[nick_len] = '\0';
      }

      // Check if we're in that channel and have ops
      chan_t *c = channel_find(state, channel);
      if (c && c->status == C_IN) {
        if (c->i_am_opped) {
          log_message(L_INFO, state,
                      "[HUB] Granting ops to %s in %s (hub request)\n", nick,
                      channel);
          irc_printf(state, "MODE %s +o %s\r\n", channel, nick);
        } else {
          log_message(L_INFO, state,
                      "[HUB] Cannot grant ops to %s in %s - I'm not opped\n",
                      nick, channel);
        }
      } else {
        log_message(L_INFO, state,
                    "[HUB] Cannot grant ops - not in channel %s\n", channel);
      }
    } else {
      log_message(L_INFO, state, "[HUB] Invalid OP_GRANT payload\n");
    }
  } break;

  case CMD_OP_FAILED:
    log_message(L_INFO, state, "[HUB] Op request failed: %s\n", payload);
    // Clear pending immediately so channel_manager retries in ~30 seconds
    for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
      if (c->op_request_pending) {
        c->op_request_pending = false;
        c->last_op_request_time = time(NULL) - 30;
      }
    }
    break;

  case CMD_INVITE_REQUEST:
    if (payload && payload_len > 0) {
      char inv_nick[MAX_NICK], inv_chan[MAX_CHAN];
      if (sscanf(payload, "%9[^|]|%64[^\n]", inv_nick, inv_chan) == 2) {
        chan_t *ic = channel_find(state, inv_chan);
        if (ic && ic->status == C_IN) {
          if (ic->i_am_opped) {
            log_message(L_INFO, state,
                        "[INVITE] Inviting %s into %s (hub request)\n",
                        inv_nick, inv_chan);
            irc_printf(state, "INVITE %s %s\r\n", inv_nick, inv_chan);
          }
        }
      }
    }
    break;

  case CMD_CHAN_ACTION:
    /* id|kind|channel|requester_uuid|nick|hostmask — another bot is locked
     * out of a channel and the hub is asking whoever can help.  Every field
     * past the kind was filled in by the hub from its own records. */
    if (payload && payload_len > 0) {
      char a_id[64], a_kind[16], a_chan[MAX_CHAN], a_uuid[64];
      char a_nick[MAX_NICK] = "", a_mask[MAX_MASK_LEN] = "";
      int n = sscanf(payload, "%63[^|]|%15[^|]|%64[^|]|%63[^|]|%9[^|]|%255[^|]",
                     a_id, a_kind, a_chan, a_uuid, a_nick, a_mask);
      if (n >= 4) {
        chan_req_kind_t k = chan_req_kind_from_token(a_kind);
        if (k < CHAN_REQ_KIND_COUNT)
          chan_access_service(state, a_id, k, a_chan, a_uuid, a_nick, a_mask,
                              NULL);
        else
          log_message(L_DEBUG, state,
                      "[DEBUG] [CHANREQ] Unknown action kind '%s'\n", a_kind);
      } else {
        log_message(L_INFO, state, "[CHANREQ] Malformed CHAN_ACTION\n");
      }
    }
    break;

  case CMD_CHAN_REPLY:
    /* id|kind|channel|status|data — the answer to something we asked for. */
    if (payload && payload_len > 0) {
      char r_id[64], r_kind[16], r_chan[MAX_CHAN], r_status[16];
      if (sscanf(payload, "%63[^|]|%15[^|]|%64[^|]|%15[^|]", r_id, r_kind,
                 r_chan, r_status) == 4) {
        /* The data field is whatever follows the 4th '|', never re-split: a
         * channel key may legitimately contain one. */
        const char *data = "";
        int bars = 0;
        for (const char *p = payload; *p; p++)
          if (*p == '|' && ++bars == 4) {
            data = p + 1;
            break;
          }
        if (chan_req_kind_from_token(r_kind) == CHAN_REQ_KEY &&
            strcmp(r_status, "ok") == 0)
          chan_access_accept_key(state, r_chan, data);
        else
          log_message(L_DEBUG, state,
                      "[DEBUG] [CHANREQ] Reply %s for %s: %s\n", r_kind, r_chan,
                      r_status);
      }
    }
    break;

  case CMD_BOT_MSG:
    if (payload && payload_len > 0) {
      log_message(L_DEBUG, state,
                  "[BOT-COMM] Received relayed bot command via hub (%d bytes)\n",
                  payload_len);
      bot_comms_process_payload(state, payload);
    }
    break;

  case CMD_UPGRADE_PREPARE:
    if (payload && payload_len > 0) hub_client_handle_upgrade_prepare(state, payload);
    break;

  case CMD_UPGRADE_COMMIT:
    if (payload && payload_len > 0) hub_client_handle_upgrade_commit(state, payload);
    break;

  case CMD_UPGRADE_ABORT:
    if (payload && payload_len > 0) hub_client_handle_upgrade_abort(state, payload);
    break;
  }
}

void hub_client_connect(bot_state_t *state) {
  if (state->hub_count == 0 || state->hub_fd != -1 || state->hub_connecting)
    return;
  // Safety: Ensure hub_count is positive before rand() % state->hub_count
  if (state->hub_count <= 0)
    return;
  if (state->bot_uuid[0] == '\0') {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: UUID not set (it is generated at bot "
                "creation — re-run 'ircbot -setup').\n");
    state->last_hub_connect_attempt =
        time(NULL) + 3600; // Don't retry for 1 hour
    return;
  }

  // Validate UUID format (36 chars, dashes in right places)
  if (strlen(state->bot_uuid) != 36 || state->bot_uuid[8] != '-' ||
      state->bot_uuid[13] != '-' || state->bot_uuid[18] != '-' ||
      state->bot_uuid[23] != '-') {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: Invalid UUID format (%s). Re-run "
                "'ircbot -setup' to regenerate identity.\n",
                state->bot_uuid);
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Check 2: Bot's own keypair must be present and the right length
  if (state->hub_key[0] == '\0') {
    log_message(
        L_INFO, state,
        "[HUB] Cannot connect: bot keypair not set (generated at creation — "
        "re-run 'ircbot -setup').\n");
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Curve25519 combined key is exactly 88 chars base64
  size_t key_len = strlen(state->hub_key);
  if (key_len != COMBINED_KEY_B64) {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: bot key length wrong (%zu chars, need "
                "%d). Re-run 'ircbot -setup' to regenerate identity.\n",
                key_len, COMBINED_KEY_B64);
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Check 3: Hub list must have at least one entry
  if (state->hubs[0].addr[0] == '\0') {
    log_message(
        L_INFO, state,
        "[HUB] Cannot connect: No hubs configured. Use '+hub <host:port> "
        "<pubkey>'.\n");
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }
  time_t now = time(NULL);
  if (now - state->last_hub_connect_attempt < HUB_RECONNECT_DELAY)
    return;
  static volatile int lock = 0;
  if (__sync_lock_test_and_set(&lock, 1))
    return;
  state->last_hub_connect_attempt = now;
  state->hub_connecting = true;
  char hub_tmp[256];
  char hub_original[256]; // Save original hub string for later
  int hub_idx = rand() % state->hub_count;
  snprintf(hub_tmp, sizeof(hub_tmp), "%s", state->hubs[hub_idx].addr);
  snprintf(hub_original, sizeof(hub_original), "%s", hub_tmp);

  /* Load this hub's pinned pubkey so the handshake-verification code (which
   * reads hub_remote_ed_pub) authenticates against the right per-hub key.
   * If the selected hub has no pinned key we refuse: the bot must be able to
   * verify the hub's signature. */
  if (state->hubs[hub_idx].ed_pub_set) {
    memcpy(state->hub_remote_ed_pub, state->hubs[hub_idx].ed_pub, 32);
    state->hub_remote_ed_pub_set = true;
  } else {
    state->hub_remote_ed_pub_set = false;
    log_message(L_INFO, state,
                "[HUB] Cannot connect to %s: no pinned pubkey. Re-add with "
                "'+hub %s <pubkey>'.\n", hub_tmp, hub_tmp);
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    state->last_hub_connect_attempt = time(NULL) + 60;
    return;
  }
  char *p = strrchr(hub_tmp, ':');
  if (!p) {
    log_message(L_INFO, state, "[HUB] Invalid hub address (missing port): %s\n",
                hub_tmp);
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }
  *p = '\0';
  const char *host = hub_tmp;
  const char *port_str = p + 1;

  /* Accept either a literal IP (v4/v6) or a DNS name here: getaddrinfo()
   * handles both, so there's no need to special-case inet_pton() first. */
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int gai_err = getaddrinfo(host, port_str, &hints, &res);
  if (gai_err != 0) {
    log_message(L_INFO, state, "[HUB] Cannot resolve hub address '%s': %s\n",
                host, gai_strerror(gai_err));
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }

  int sockfd = -1;
  bool connected = false;
  int flags = 0;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sockfd < 0) continue;

    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int conn_result = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
    if (conn_result == 0) {
      connected = true;
    } else if (errno == EINPROGRESS) {
      fd_set writefds;
      struct timeval timeout;
      FD_ZERO(&writefds);
      FD_SET(sockfd, &writefds);
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      int sel = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
      if (sel > 0) {
        int so_error;
        socklen_t solen = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &solen);
        if (so_error == 0) connected = true;
      }
    }

    if (connected) break;
    close(sockfd);
    sockfd = -1;
  }
  freeaddrinfo(res);

  if (!connected) {
    log_message(L_INFO, state, "[HUB] Failed to connect to %s:%s\n", host,
                port_str);
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }

  fcntl(sockfd, F_SETFL, flags);

  state->hub_fd = sockfd;
  state->hub_connected = true;
  state->hub_authenticated = false;
  auth_state = HUB_AUTH_NONE;
  snprintf(state->current_hub, sizeof(state->current_hub), "%s", hub_original);

  int uuid_len = strlen(state->bot_uuid);
  uint32_t net_len = htonl(uuid_len);
  unsigned char uuid_frame[4 + 36];
  memcpy(uuid_frame, &net_len, 4);
  memcpy(uuid_frame + 4, state->bot_uuid, uuid_len);
  if (send(state->hub_fd, uuid_frame, 4 + uuid_len, 0) == 4 + uuid_len) {
    auth_state = HUB_AUTH_SENT_UUID;
    log_message(L_INFO, state, "[HUB] Connected to %s.\n", state->current_hub);
  } else {
    hub_client_disconnect(state);
  }
  state->hub_connecting = false;
  __sync_lock_release(&lock);
}

void hub_client_process(bot_state_t *state) {
  if (state->hub_count == 0 || state->hub_fd == -1)
    return;

  unsigned char header[4];
  int header_read = 0;
  while (header_read < 4) {
    int n = recv(state->hub_fd, header + header_read, 4 - header_read, 0);
    if (n <= 0) {
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return;
      hub_client_disconnect(state);
      return;
    }
    header_read += n;
  }
  uint32_t net_len;
  memcpy(&net_len, header, 4);
  int packet_len = ntohl(net_len);
  /* Change 5: a CMD_CONFIG_DATA frame from the hub can exceed MAX_BUFFER at
   * scale — bound by the config-frame ceiling instead of the small wire size. */
  if (packet_len <= 0 || packet_len > MAX_HUB_FRAME) {
    hub_client_disconnect(state);
    return;
  }
  unsigned char *packet_body = malloc(packet_len);
  if (!packet_body) {
    hub_client_disconnect(state);
    return;
  }
  int total_read = 0;
  while (total_read < packet_len) {
    int r = recv(state->hub_fd, packet_body + total_read,
                 packet_len - total_read, 0);
    if (r <= 0) {
      if (r < 0 && errno == EINTR) continue;
      free(packet_body);
      hub_client_disconnect(state);
      return;
    }
    total_read += r;
  }
  if (!state->hub_authenticated) {
    if (auth_state == HUB_AUTH_SENT_UUID) {
      /* v2 layout: challenge(32) || hub_eph_pub(32) || hub_sig(64)    (128 bytes)
       *
       * hub_sig = Ed25519_sign(hub_ed_priv,
       *   "irchub-hub-auth-v2|" || bot_uuid || "|" || challenge || eph_pub).
       * Verified against state->hub_remote_ed_pub (required — bot refuses to
       * connect if not set; see hub_client_connect precondition). */
      if (packet_len != 128) {
        log_message(L_INFO, state,
                    "[HUB] Expected 128-byte v2 challenge, got %d bytes\n",
                    packet_len);
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
      const unsigned char *challenge   = packet_body;
      const unsigned char *hub_eph_pub = packet_body + 32;

      if (state->hub_remote_ed_pub_set) {
        /* Verify the hub's signature before deriving the session key. */
        const unsigned char *hub_sig = packet_body + 64;

        size_t uuid_len = strlen(state->bot_uuid);
        size_t tlen = strlen("irchub-hub-auth-v2|") + uuid_len + 1 + 32 + 32;
        unsigned char *transcript = malloc(tlen);
        if (!transcript) {
          free(packet_body);
          hub_client_disconnect(state);
          return;
        }
        size_t off = 0;
        memcpy(transcript + off, "irchub-hub-auth-v2|", 19); off += 19;
        memcpy(transcript + off, state->bot_uuid, uuid_len); off += uuid_len;
        transcript[off++] = '|';
        memcpy(transcript + off, challenge, 32);   off += 32;
        memcpy(transcript + off, hub_eph_pub, 32); off += 32;

        EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, NULL, state->hub_remote_ed_pub, 32);
        EVP_MD_CTX *md = pk ? EVP_MD_CTX_new() : NULL;
        bool sig_ok = false;
        if (md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, pk) == 1 &&
            EVP_DigestVerify(md, hub_sig, 64, transcript, off) == 1) {
          sig_ok = true;
        }
        if (md) EVP_MD_CTX_free(md);
        if (pk) EVP_PKEY_free(pk);
        memset(transcript, 0, off);
        free(transcript);

        if (!sig_ok) {
          log_message(L_INFO, state,
                      "[HUB] v2 hub signature INVALID — possible MITM. "
                      "Disconnecting.\n");
          free(packet_body);
          hub_client_disconnect(state);
          return;
        }
        log_message(L_INFO, state, "[HUB] v2 hub signature verified.\n");
      } else {
        /* hub_remote_ed_pub_set is false — no pinned key for this hub.
         * (The connect path normally refuses earlier; this is defensive.)
         * Re-add the hub with its pubkey: '+hub <host:port> <pubkey>'. */
        log_message(L_INFO, state,
                    "[HUB] ERROR: hub pubkey not pinned. "
                    "Re-add with '+hub <host:port> <pubkey>' before "
                    "connecting.\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }

      // Derive session key from X25519 + HKDF before signing
      unsigned char session_key[32];
      if (!x25519_derive_session_key(state, hub_eph_pub, challenge, session_key)) {
        log_message(L_INFO, state, "[HUB] Failed to derive session key\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
      memcpy(state->hub_session_key, session_key, 32);
      secure_wipe(session_key, 32);

      // Sign the domain-separated challenge with Ed25519
      unsigned char sig[64];
      if (!ed25519_sign_challenge(state, challenge, hub_eph_pub, sig)) {
        log_message(L_INFO, state, "[HUB] Failed to sign challenge\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }

      // Send 64-byte signature, length-framed
      unsigned char sig_frame[4 + 64];
      uint32_t sig_net_len = htonl(64);
      memcpy(sig_frame, &sig_net_len, 4);
      memcpy(sig_frame + 4, sig, 64);
      if (send(state->hub_fd, sig_frame, 4 + 64, 0) == 4 + 64) {
        auth_state = HUB_AUTH_SENT_SIGNATURE;
        log_message(L_INFO, state, "[HUB] Ed25519 signature sent.\n");
      } else {
        log_message(L_INFO, state, "[HUB] Failed to send signature\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
    } else if (auth_state == HUB_AUTH_SENT_SIGNATURE) {
      if (packet_len >= GCM_IV_LEN + 1 + GCM_TAG_LEN) {
        unsigned char ack_tag[GCM_TAG_LEN];
        unsigned char ack_pt[8] = {0};
        memcpy(ack_tag, packet_body + packet_len - GCM_TAG_LEN, GCM_TAG_LEN);
        int ack_pl = crypto_aes_gcm_decrypt(
            packet_body, packet_len - GCM_TAG_LEN,
            state->hub_session_key, ack_pt, ack_tag);
        if (ack_pl == 1 && ack_pt[0] == 0x01) {
          state->hub_authenticated = true;
          auth_state = HUB_AUTH_COMPLETE;
          state->last_hub_activity = time(NULL);
          state->hub_connect_time = time(NULL);
          log_message(L_INFO, state, "[HUB] Authenticated (Curve25519 v2)!\n");
          hub_client_push_config(state);
          /* This hub has no presence for us yet, so report unconditionally
           * rather than waiting for the heartbeat's change check. */
          hub_client_send_presence(state, true);
          /* If this process is the product of a hub-driven upgrade, close
           * that run out now that there is a hub to tell. */
          hub_client_report_upgrade_result(state);
          if (state->admin_delta_pending) {
            /* After the config push (so the hub already knows v|2).  LWW
             * on the hub: only records changed here since carry a newer
             * timestamp and win; the rest are no-ops. */
            log_message(L_INFO, state, "[HUB] Pushing user/mask changes made "
                                       "while the hub was unreachable\n");
            hub_client_push_admin_delta(state);
          }
        } else {
          log_message(L_INFO, state,
                      "[HUB] v2 ACK decrypt/parse failed (len=%d)\n", ack_pl);
          free(packet_body);
          hub_client_disconnect(state);
          return;
        }
      } else {
        log_message(L_INFO, state, "[HUB] Bad ACK from hub (len=%d)\n", packet_len);
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
    }
    free(packet_body);
    return;
  }
  state->last_hub_activity = time(NULL);
  /* Change 5: decrypt scratch sized to the largest inbound hub frame.  static
   * (not stack) — the bot is single-threaded and this path is non-reentrant, so
   * a ~200 KB frame needs no oversized stack allocation. */
  static unsigned char plain[MAX_HUB_FRAME];
  unsigned char tag[GCM_TAG_LEN];
  if (packet_len > (GCM_IV_LEN + GCM_TAG_LEN)) {
    memcpy(tag, packet_body + packet_len - GCM_TAG_LEN, GCM_TAG_LEN);
    int plain_len =
        crypto_aes_gcm_decrypt(packet_body, packet_len - GCM_TAG_LEN,
                               state->hub_session_key, plain, tag);
    if (plain_len > 0) {
      unsigned char cmd = plain[0];

      if (cmd == CMD_PING) {
        // RATE LIMIT: Only respond to ping once per 5 seconds
        time_t now = time(NULL);
        if (now - last_pong_sent >= 5) {
          unsigned char pong_plain[16] = {0};
          pong_plain[0] = CMD_PING;
          uint32_t zero = 0;
          memcpy(&pong_plain[1], &zero, 4);
          unsigned char pong_buf[128], pong_tag[GCM_TAG_LEN];
          int pong_enc = crypto_aes_gcm_encrypt(
              pong_plain, 5, state->hub_session_key, pong_buf + 4, pong_tag);
          if (pong_enc > 0) {
            memcpy(pong_buf + 4 + pong_enc, pong_tag, GCM_TAG_LEN);
            uint32_t pong_len = htonl(pong_enc + GCM_TAG_LEN);
            memcpy(pong_buf, &pong_len, 4);
            if (send(state->hub_fd, pong_buf, 4 + pong_enc + GCM_TAG_LEN, 0) <= 0) {
              hub_client_disconnect(state);
              free(packet_body);
              return;
            }
            last_pong_sent = now;
          }
        }
      } else {
        // Extract payload from plain[5...] and call handler
        if (plain_len > 5) {
          uint32_t payload_len_network;
          memcpy(&payload_len_network, &plain[1], 4);
          int payload_len = ntohl(payload_len_network);

          if (payload_len > 0 && payload_len <= (plain_len - 5)) {
            /* Change 5: static, sized to the largest inbound frame (see plain
             * above). payload_len <= plain_len-5 <= MAX_HUB_FRAME-5. */
            static char payload_buf[MAX_HUB_FRAME];
            memcpy(payload_buf, &plain[5], payload_len);
            payload_buf[payload_len] = '\0';

            hub_handle_response(state, cmd, payload_buf, payload_len);
          }
        }
      }
    } else {
      free(packet_body);
      hub_client_disconnect(state);
      return;
    }
  }
  free(packet_body);
}
