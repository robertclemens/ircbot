#define _POSIX_C_SOURCE 200809L
#include "bot.h"
#include <arpa/inet.h>
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

// Decode the 88-char base64 combined key (64 bytes) into separate halves
static bool hub_key_decode(bot_state_t *state, unsigned char ed_priv[32],
                           unsigned char x_priv[32]) {
  int dec_len = 0;
  unsigned char *dec = base64_decode(state->hub_key, &dec_len);
  if (!dec || dec_len != HUB_KEY_RAW_LEN) {
    log_message(L_INFO, state, "[HUB] hub_key is not a valid 64-byte Curve25519 key\n");
    if (dec) free(dec);
    return false;
  }
  memcpy(ed_priv, dec,      32);
  memcpy(x_priv,  dec + 32, 32);
  memset(dec, 0, 64);
  free(dec);
  return true;
}

// Sign a 32-byte challenge with the Ed25519 private key; sig_out is 64 bytes
static bool ed25519_sign_challenge(bot_state_t *state,
                                   const unsigned char *challenge,
                                   unsigned char sig_out[64]) {
  unsigned char ed_priv[32], x_priv[32];
  if (!hub_key_decode(state, ed_priv, x_priv)) return false;
  memset(x_priv, 0, 32);

  EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ed_priv, 32);
  memset(ed_priv, 0, 32);
  if (!pk) {
    log_message(L_INFO, state, "[HUB] Failed to load Ed25519 private key\n");
    return false;
  }
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  bool ok = false;
  size_t siglen = 64;
  if (md && EVP_DigestSignInit(md, NULL, NULL, NULL, pk) == 1
         && EVP_DigestSign(md, sig_out, &siglen, challenge, 32) == 1
         && siglen == 64)
    ok = true;
  if (md) EVP_MD_CTX_free(md);
  EVP_PKEY_free(pk);
  if (!ok) log_message(L_INFO, state, "[HUB] Ed25519 signing failed\n");
  return ok;
}

// Derive session key: X25519(bot_x_priv, hub_eph_pub) → HKDF → session_key
static bool x25519_derive_session_key(bot_state_t *state,
                                      const unsigned char hub_eph_pub[32],
                                      const unsigned char challenge[32],
                                      unsigned char session_key_out[32]) {
  unsigned char ed_priv[32], x_priv[32];
  if (!hub_key_decode(state, ed_priv, x_priv)) return false;
  memset(ed_priv, 0, 32);

  // X25519 ECDH
  EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, x_priv, 32);
  EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, hub_eph_pub, 32);
  memset(x_priv, 0, 32);
  bool ok = false;
  unsigned char shared[32];

  if (priv && peer) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t len = 32;
    if (ctx && EVP_PKEY_derive_init(ctx) == 1
            && EVP_PKEY_derive_set_peer(ctx, peer) == 1
            && EVP_PKEY_derive(ctx, shared, &len) == 1
            && len == 32)
      ok = true;
    if (ctx) EVP_PKEY_CTX_free(ctx);
  }
  if (priv) EVP_PKEY_free(priv);
  if (peer) EVP_PKEY_free(peer);
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
  memset(shared, 0, 32);
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
  memset(state->hub_session_key, 0, 32);
  state->current_hub[0] = '\0'; // Clear current hub tracking
  state->last_hub_connect_attempt = time(NULL);
  last_pong_sent = 0;
}

void hub_client_heartbeat(bot_state_t *state) {
  if (state->hub_count == 0 || !state->hub_connected ||
      !state->hub_authenticated || state->hub_fd == -1)
    return;
  time_t now = time(NULL);
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

/* Push a single key=value change to the hub via CMD_BOT_DELTA.
 * This is a targeted update that the hub fans out as one DELTA per peer,
 * instead of the full config push which fans out ~50 lines.  Falls back to
 * hub_client_push_config if ts == 0 or key is empty. */
void hub_client_push_delta(bot_state_t *state, const char *key,
                           const char *value, time_t ts) {
  if (!key || key[0] == '\0') return;
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) return;

  char payload[MAX_BUFFER];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s|%ld",
                         key, value ? value : "", (long)(ts ? ts : time(NULL)));
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload)) return;

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
    } else {
      log_message(L_INFO, state, "[HUB] Delta push failed, falling back\n");
      hub_client_disconnect(state);
    }
  }
}

/**
 * Generate config payload for hub sync
 * Includes: c|, m|, o|, a|, p|, h| (hostmask), n| (nick)
 * Excludes: s|, u|, g|, v|, l|, i|, k| (bot-specific)
 */
void hub_client_generate_config_payload(bot_state_t *state, char *buffer,
                                        int max_len) {
  int offset = 0;
  int written;

  // Channels
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

  /* Admin/oper/mask records are hub-authoritative — bots receive them from hub,
   * they do NOT push them back. IRC admin commands (+admin, +usermask, etc.)
   * update local state and call hub_client_push_config, but only the bot-local
   * fields (channels, nick, hostmask) are included in the push payload.
   * The hub manages a|/o|/m| records via CMD_ADMIN_* commands only. */

  // Bot communication password (p| line, unchanged)
  if (state->bot_comm_pass[0] != '\0') {
    written = snprintf(buffer + offset, max_len - offset, "p|%s|%ld\n",
                       state->bot_comm_pass, (long)state->bot_comm_pass_ts);
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
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

/* Route an encrypted bot command to a specific bot by UUID via hub relay.
 * encoded_cipher and encoded_tag are the base64 strings from bot_comms.
 * Returns true if the frame was sent to the hub; false to fall back to PRIVMSG. */
bool hub_client_relay_bot_command(bot_state_t *state, const char *target_uuid,
                                  const char *encoded_cipher,
                                  const char *encoded_tag) {
  if (!state->hub_connected || !state->hub_authenticated ||
      state->hub_fd == -1)
    return false;

  char payload[MAX_BUFFER];
  int pay_len = snprintf(payload, sizeof(payload), "%s|%s:%s",
                         target_uuid, encoded_cipher, encoded_tag);
  if (pay_len <= 0 || pay_len >= (int)sizeof(payload)) return false;

  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_BOT_RELAY;
  uint32_t inner_len = htonl((uint32_t)pay_len);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, pay_len);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + pay_len, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl((uint32_t)(cipher_len + GCM_TAG_LEN));
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total) {
      log_message(L_DEBUG, state,
                  "[BOT-COMM] CMD_BOT_RELAY sent to hub for %s\n", target_uuid);
      return true;
    }
    hub_client_disconnect(state);
  }
  return false;
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

// Alias for promoting local config to hub (e.g. on connect)
void hub_client_promote_local_config(bot_state_t *state) {
  hub_client_push_config(state);
}

/* Push all user/mask records to hub via CMD_CONFIG_PUSH so the hub can store
 * and broadcast newly created or modified admin/oper/mask records.  The hub's
 * process_bot_config_push uses strict ts > stored_ts, so unchanged records
 * (same timestamp) are silently rejected — only new or modified ones land. */
void hub_client_push_admin_delta(bot_state_t *state) {
  if (!state->hub_authenticated || state->hub_fd == -1) return;

  char payload[MAX_BUFFER];
  int offset = 0;
  int remaining = (int)sizeof(payload);

  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *u = &state->user_records[i];
    int w = snprintf(payload + offset, (size_t)remaining,
                     "%c|%s|%s|%s|%s|%ld|%ld\n",
                     u->type, u->uuid, u->name, u->password,
                     u->is_active ? "add" : "del",
                     (long)u->last_seen, (long)u->timestamp);
    if (w > 0 && w < remaining) { offset += w; remaining -= w; }
  }
  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *m = &state->mask_records[i];
    int w = snprintf(payload + offset, (size_t)remaining,
                     "m|%s|%s|%s|%ld|%ld\n",
                     m->uuid, m->mask,
                     m->is_active ? "add" : "del",
                     (long)m->last_used, (long)m->timestamp);
    if (w > 0 && w < remaining) { offset += w; remaining -= w; }
  }

  if (offset == 0) return;

  unsigned char plain[MAX_BUFFER];
  plain[0] = (unsigned char)CMD_CONFIG_PUSH;
  uint32_t inner_len = htonl((uint32_t)offset);
  memcpy(&plain[1], &inner_len, 4);
  memcpy(&plain[5], payload, (size_t)offset);

  unsigned char cipher[MAX_BUFFER], tag[GCM_TAG_LEN];
  int cipher_len = crypto_aes_gcm_encrypt(
      plain, 5 + offset, state->hub_session_key, cipher + 4, tag);

  if (cipher_len > 0) {
    memcpy(cipher + 4 + cipher_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl((uint32_t)(cipher_len + GCM_TAG_LEN));
    memcpy(cipher, &net_len, 4);
    int total = 4 + cipher_len + GCM_TAG_LEN;
    if (send(state->hub_fd, cipher, total, 0) == total)
      log_message(L_INFO, state, "[HUB] Admin delta pushed (%d user, %d mask records)\n",
                  state->user_record_count, state->mask_record_count);
    else
      hub_client_disconnect(state);
  }
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

void hub_client_process_config_data(bot_state_t *state, const char *payload) {
  log_message(L_DEBUG, state, "[HUB-SYNC] Processing config data from hub\n");

  /* Hub is authoritative for user/mask records. Replace rather than merge so
   * the bot always has exactly the hub's current set — no stale or duplicate
   * UUIDs from a previous sync can accumulate. Preserve last_seen/last_used
   * that were updated locally since the last hub push. */
  user_record_t saved_users[MAX_USER_RECORDS];
  mask_record_t saved_masks[MAX_USER_MASKS];
  int saved_user_count = state->user_record_count;
  int saved_mask_count = state->mask_record_count;
  memcpy(saved_users, state->user_records, sizeof(user_record_t) * (size_t)saved_user_count);
  memcpy(saved_masks, state->mask_records, sizeof(mask_record_t) * (size_t)saved_mask_count);
  state->user_record_count = 0;
  state->mask_record_count = 0;

  char work_buf[MAX_BUFFER];
  snprintf(work_buf, sizeof(work_buf), "%s", payload);

  char *saveptr;
  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;

  while (line) {
    if (strlen(line) < 2 || line[0] == '#') {
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
      long ts;
      int parsed;
      int modes_val = 0;

      /* Try new 5-field format: chan|key|modes|op|ts */
      parsed = sscanf(data, "%64[^|]|%30[^|]|%d|%7[^|]|%ld",
                      chan, key, &modes_val, op, &ts);
      if (parsed < 5) {
        /* Try new 5-field without key: chan||modes|op|ts */
        modes_val = 0;
        parsed = sscanf(data, "%64[^|]||%d|%7[^|]|%ld",
                        chan, &modes_val, op, &ts);
        if (parsed >= 4) {
          key[0] = '\0';
        } else {
          /* Fall back to old 4-field: chan|key|op|ts */
          modes_val = 0;
          parsed = sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%ld",
                          chan, key, op, &ts);
          if (parsed < 3) {
            /* Old 4-field without key: chan||op|ts */
            parsed = sscanf(data, "%64[^|]||%7[^|]|%ld", chan, op, &ts);
            key[0] = '\0';
          }
        }
      }

      if (parsed >= 3) {
        bool is_add = (strcmp(op, "add") == 0);
        chan_t *c = channel_find(state, chan);

        log_message(L_DEBUG, state, "[HUB-SYNC] Channel %s: hub_ts=%ld local_ts=%ld op=%s\n",
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
          // Compare timestamps
          if (ts > c->timestamp) {
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
            log_message(L_DEBUG, state, "[HUB-SYNC] Rejected channel %s: hub_ts=%ld <= local_ts=%ld\n",
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
          long last_used, ts;
          snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(p1-data),data);
          snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(act,    sizeof(act),    "%.*s",(int)(p3-p2-1),p2+1);
          last_used = atol(p3+1); ts = atol(p4+1);
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
          if (found_m && ts > found_m->timestamp) {
            found_m->is_active = is_active;
            if (last_used > found_m->last_used) found_m->last_used = last_used;
            found_m->timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Synced mask %s (%s)\n", mask_s, act);
          }
        }
      }
    } break;

    case 'o': // Oper user record (new: uuid|name|pass|add/del|last_seen|ts)
    case 'a': // Admin user record (new: uuid|name|pass|add/del|last_seen|ts)
    {
      char first_ua[40] = {0};
      char *pfua = strchr(data, '|');
      if (pfua) { size_t fl=(size_t)(pfua-data); if(fl<sizeof(first_ua)){memcpy(first_ua,data,fl);first_ua[fl]=0;} }
      bool is_new_ua = (strlen(first_ua)==36 && first_ua[8]=='-' && first_ua[13]=='-' && first_ua[18]=='-' && first_ua[23]=='-');
      if (is_new_ua) {
        char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
        char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
        char *p5=p4?strchr(p4+1,'|'):NULL;
        if (p1&&p2&&p3&&p4&&p5) {
          char uuid[37], uname[64], upass[MAX_PASS], act[8];
          long last_seen, ts;
          snprintf(uuid,  sizeof(uuid),  "%.*s",(int)(p1-data),data);
          snprintf(uname, sizeof(uname), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(upass, sizeof(upass), "%.*s",(int)(p3-p2-1),p2+1);
          snprintf(act,   sizeof(act),   "%.*s",(int)(p4-p3-1),p3+1);
          last_seen = atol(p4+1); ts = atol(p5+1);
          bool is_active = (strncmp(act,"add",3)==0);
          user_record_t *found_u = NULL;
          for (int ui=0; ui<state->user_record_count; ui++) {
            if (strcmp(state->user_records[ui].uuid,uuid)==0) {
              found_u = &state->user_records[ui]; break;
            }
          }
          if (!found_u && state->user_record_count < MAX_USER_RECORDS) {
            found_u = &state->user_records[state->user_record_count++];
            memset(found_u,0,sizeof(*found_u));
            snprintf(found_u->uuid,sizeof(found_u->uuid),"%s",uuid);
          }
          if (found_u && ts > found_u->timestamp) {
            snprintf(found_u->name,     sizeof(found_u->name),     "%s",uname);
            snprintf(found_u->password, sizeof(found_u->password), "%s",upass);
            found_u->type      = type;
            found_u->is_active = is_active;
            if (last_seen > found_u->last_seen) found_u->last_seen = last_seen;
            found_u->timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Synced user %s (%c/%s)\n", uname, type, act);
          }
        }
      }
    } break;

    case 'p': // Bot password: p|password|timestamp
    {
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        snprintf(pass, sizeof(pass), "%s", data);
        ts = 0;
      }
      log_message(L_DEBUG, state, "[HUB-SYNC] BotPass: hub_ts=%ld local_ts=%ld\n",
                  ts, (long)state->bot_comm_pass_ts);
      // Only update if hub has newer timestamp
      if (ts > state->bot_comm_pass_ts || state->bot_comm_pass[0] == '\0') {
        snprintf(state->bot_comm_pass, sizeof(state->bot_comm_pass), "%s", pass);
        state->bot_comm_pass_ts = ts;
        updates++;
        log_message(L_INFO, state, "[HUB] Updated bot password (ts=%ld)\n", ts);
      } else {
        log_message(L_DEBUG, state, "[HUB-SYNC] Rejected bot password: hub_ts=%ld <= local_ts=%ld\n",
                    ts, (long)state->bot_comm_pass_ts);
      }
    } break;

    case 'b': // Bot line: b|hostmask|uuid|timestamp
    {
      // hub_generate_bot_payload sends: b|<hostmask>|<uuid>|<ts>
      char hostmask[MAX_MASK_LEN];
      char uuid[64];
      long ts = 0;
      hostmask[0] = '\0';
      uuid[0] = '\0';

      log_message(L_DEBUG, state, "[HUB-SYNC] Processing bot line\n");

      int parsed = sscanf(data, "%255[^|]|%63[^|]|%ld", hostmask, uuid, &ts);
      log_message(L_DEBUG, state,
                  "[HUB-SYNC] Parsed %d fields: hostmask='%s' uuid='%s' ts=%ld\n",
                  parsed, hostmask, uuid, ts);
      if (parsed < 1) {
        snprintf(hostmask, sizeof(hostmask), "%s", data);
      }

      if (hostmask[0] != '\0') {
        // Find existing entry: prefer UUID match (handles nick/host changes),
        // fall back to hostmask match.  Also sweep out any duplicate entries
        // for the same UUID so stale masks from previous sessions don't linger.
        int existing_idx = -1;

        if (uuid[0] != '\0') {
          for (int i = 0; i < state->trusted_bot_count; i++) {
            char ex_uuid[64];
            if (sscanf(state->trusted_bots[i], "%*[^|]|%63[^|]", ex_uuid) >= 1 &&
                strcmp(ex_uuid, uuid) == 0) {
              if (existing_idx == -1) {
                existing_idx = i; // keep first match
              } else {
                // Remove duplicate: shift array down and free
                free(state->trusted_bots[i]);
                memmove(&state->trusted_bots[i],
                        &state->trusted_bots[i + 1],
                        (state->trusted_bot_count - i - 1) * sizeof(char *));
                state->trusted_bot_count--;
                i--;
              }
            }
          }
        }

        // Fall back to hostmask match if no UUID match found
        if (existing_idx == -1) {
          for (int i = 0; i < state->trusted_bot_count; i++) {
            char ex_mask[MAX_MASK_LEN];
            if (sscanf(state->trusted_bots[i], "%255[^|]", ex_mask) >= 1 &&
                strcmp(ex_mask, hostmask) == 0) {
              existing_idx = i;
              break;
            }
          }
        }

        if (existing_idx != -1) {
          long old_ts = 0;
          sscanf(state->trusted_bots[existing_idx], "%*[^|]|%*[^|]|%ld", &old_ts);
          if (ts > old_ts) {
            char full_entry[256];
            snprintf(full_entry, sizeof(full_entry), "%s|%s|%ld", hostmask, uuid, ts);
            char *new_entry = strdup(full_entry);
            if (!new_entry) break;
            free(state->trusted_bots[existing_idx]);
            state->trusted_bots[existing_idx] = new_entry;
            updates++;
            log_message(L_INFO, state, "[HUB] Updated trusted bot: %s\n", hostmask);
          }
        } else if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
          char full_entry[256];
          snprintf(full_entry, sizeof(full_entry), "%s|%s|%ld", hostmask, uuid, ts);
          char *new_entry = strdup(full_entry);
          if (!new_entry) break;
          state->trusted_bots[state->trusted_bot_count++] = new_entry;
          updates++;
          log_message(L_INFO, state, "[HUB] Added trusted bot: %s\n", hostmask);
        }
      }
    } break;

    case 'P': // PURGE command — format: PURGE|<cutoff_epoch>
    {
      // cutoff == 0: purge all tombstones
      // cutoff  > 0: purge tombstones older than cutoff
      long cutoff_val;
      if (sscanf(data, "URGE|%ld", &cutoff_val) == 1) {
        time_t cutoff = (time_t)cutoff_val;
        int purged = 0;

        // Purge tombstoned channels (is_managed=false)
        chan_t *c = state->chanlist;
        while (c) {
          chan_t *next = c->next;
          if (!c->is_managed && (cutoff == 0 || c->timestamp < cutoff)) {
            channel_remove(state, c->name);
            purged++;
          }
          c = next;
        }

        // Purge tombstoned user records (admins/opers)
        for (int i = 0; i < state->user_record_count; i++) {
          if (!state->user_records[i].is_active &&
              (cutoff == 0 || state->user_records[i].timestamp < cutoff)) {
            memmove(&state->user_records[i], &state->user_records[i+1],
                    (state->user_record_count - i - 1) * sizeof(user_record_t));
            state->user_record_count--;
            purged++;
            i--;
          }
        }

        // Purge tombstoned usermask records
        for (int i = 0; i < state->mask_record_count; i++) {
          if (!state->mask_records[i].is_active &&
              (cutoff == 0 || state->mask_records[i].timestamp < cutoff)) {
            memmove(&state->mask_records[i], &state->mask_records[i+1],
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
      }
    } break;

    default:
      log_message(L_DEBUG, state, "[HUB-SYNC] Unrecognized line type '%c': %s\n", type, line);
      break;
    }

    line = strtok_r(NULL, "\n", &saveptr);
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
    log_message(L_DEBUG, state, "[HUB] Received PING from hub\n");
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
    // Hub sent us a new private key during rekey operation
    if (payload && payload_len > 0) {
      log_message(L_INFO, state,
                  "[HUB] Received new private key from hub (%d bytes)\n",
                  payload_len);

      // Validate: must be exactly COMBINED_KEY_B64 chars (Curve25519 key)
      if (payload_len == COMBINED_KEY_B64) {
        memset(state->hub_key, 0, sizeof(state->hub_key));
        memcpy(state->hub_key, payload, payload_len);
        state->hub_key[payload_len] = '\0';

        log_message(L_INFO, state, "[HUB] Updated Curve25519 key in memory\n");

        // Save the new key to config file immediately
        if (bot_has_startup_pass(state)) {
          config_write_with_state_pass(state);
          log_message(L_INFO, state,
                      "[HUB] Saved new private key to config file\n");
          log_message(L_INFO, state,
                      "[HUB] Key update complete - waiting for hub to disconnect\n");
        } else {
          log_message(L_INFO, state,
                      "[HUB] WARNING: Cannot save config (no password), key update "
                      "will be lost on restart\n");
        }
      } else {
        log_message(L_INFO, state,
                    "[HUB] ERROR: New key wrong length (%d, need %d chars)\n",
                    payload_len, COMBINED_KEY_B64);
      }
    }
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

  case CMD_BOT_MSG:
    if (payload && payload_len > 0) {
      log_message(L_DEBUG, state,
                  "[BOT-COMM] Received relayed bot command via hub (%d bytes)\n",
                  payload_len);
      bot_comms_process_payload(state, payload);
    }
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
                "[HUB] Cannot connect: UUID not set. Use 'setuuid' command.\n");
    state->last_hub_connect_attempt =
        time(NULL) + 3600; // Don't retry for 1 hour
    return;
  }

  // Validate UUID format (36 chars, dashes in right places)
  if (strlen(state->bot_uuid) != 36 || state->bot_uuid[8] != '-' ||
      state->bot_uuid[13] != '-' || state->bot_uuid[18] != '-' ||
      state->bot_uuid[23] != '-') {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: Invalid UUID format (%s). Use 'setuuid' "
                "command.\n",
                state->bot_uuid);
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Check 2: Hub key must be present and reasonable length
  if (state->hub_key[0] == '\0') {
    log_message(
        L_INFO, state,
        "[HUB] Cannot connect: Hub key not set. Use 'sethubkey' command.\n");
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Curve25519 combined key is exactly 88 chars base64
  size_t key_len = strlen(state->hub_key);
  if (key_len != COMBINED_KEY_B64) {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: Hub key length wrong (%zu chars, need %d). "
                "Use 'sethubkey <88-char-base64>' to set a Curve25519 key.\n",
                key_len, COMBINED_KEY_B64);
    state->last_hub_connect_attempt = time(NULL) + 3600;
    return;
  }

  // Check 3: Hub list must have at least one entry
  if (state->hub_list[0] == NULL || state->hub_list[0][0] == '\0') {
    log_message(
        L_INFO, state,
        "[HUB] Cannot connect: No hubs configured. Use '+hub' command.\n");
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
  snprintf(hub_tmp, sizeof(hub_tmp), "%s",
           state->hub_list[rand() % state->hub_count]);
  snprintf(hub_original, sizeof(hub_original), "%s", hub_tmp);
  char *p = strchr(hub_tmp, ':');
  if (!p) {
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }
  *p = '\0';
  int port = atoi(p + 1);
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, hub_tmp, &addr.sin_addr) != 1) {
    log_message(L_INFO, state, "[HUB] Invalid hub IP address: %s\n", hub_tmp);
    close(sockfd);
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }

  int flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  int conn_result = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
  bool connected = false;
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

  if (!connected) {
    close(sockfd);
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
  if (packet_len <= 0 || packet_len > (MAX_BUFFER - 4)) {
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
      /* v1 layout: challenge(32) || hub_eph_pub(32)                    (64 bytes)
       * v2 layout: challenge(32) || hub_eph_pub(32) || hub_sig(64)    (128 bytes)
       *
       * v2's hub_sig is Ed25519_sign(hub_ed_priv,
       *   "irchub-hub-auth-v2|" || bot_uuid || "|" || challenge || eph_pub).
       * The bot verifies with state->hub_remote_ed_pub if set. When hub_pub
       * is configured but the hub sent v1, we refuse — the operator opted in
       * to mutual auth. When hub_pub is not configured, v1 is accepted with
       * a warning. */
      if (packet_len != 64 && packet_len != 128) {
        log_message(L_INFO, state,
                    "[HUB] Expected 64 or 128 byte challenge, got %d bytes\n",
                    packet_len);
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
      const unsigned char *challenge   = packet_body;
      const unsigned char *hub_eph_pub = packet_body + 32;
      const bool is_v2 = (packet_len == 128);

      if (state->hub_remote_ed_pub_set && !is_v2) {
        log_message(L_INFO, state,
                    "[HUB] Refusing v1 challenge — hub pubkey is configured "
                    "but the hub did not provide a signature. MITM risk.\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }

      if (is_v2 && state->hub_remote_ed_pub_set) {
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
      } else if (is_v2) {
        log_message(L_INFO, state,
                    "[HUB] WARN: hub sent v2 challenge but no hub pubkey "
                    "configured ('sethubpub'); signature NOT verified.\n");
      } else {
        log_message(L_INFO, state,
                    "[HUB] WARN: legacy v1 (unsigned) challenge accepted. "
                    "Configure 'sethubpub' to enable mutual auth.\n");
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
      memset(session_key, 0, 32);

      // Sign the challenge with Ed25519
      unsigned char sig[64];
      if (!ed25519_sign_challenge(state, challenge, sig)) {
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
      /* Two ACK formats:
       *   v1: 1-byte plaintext 0x01 (legacy)
       *   v2: GCM-encrypted (IV || ciphertext || tag). On the wire that's
       *       always at least GCM_IV_LEN + 1 + GCM_TAG_LEN bytes. */
      if (packet_len == 1 && packet_body[0] == 0x01) {
        if (state->hub_remote_ed_pub_set) {
          log_message(L_INFO, state,
                      "[HUB] Refusing v1 plaintext ACK — hub pubkey configured.\n");
          free(packet_body);
          hub_client_disconnect(state);
          return;
        }
        state->hub_authenticated = true;
        auth_state = HUB_AUTH_COMPLETE;
        state->last_hub_activity = time(NULL);
        state->hub_connect_time = time(NULL);
        log_message(L_INFO, state, "[HUB] Authenticated (Curve25519 v1)!\n");
        hub_client_push_config(state);
      } else if (packet_len >= GCM_IV_LEN + 1 + GCM_TAG_LEN) {
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
  unsigned char plain[MAX_BUFFER], tag[GCM_TAG_LEN];
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
            char payload_buf[MAX_BUFFER];
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
