#define _POSIX_C_SOURCE 200809L
#include "bot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

extern char *base64_encode(const unsigned char *input, int length);
extern unsigned char *base64_decode(const char *input, int *out_len);
extern int crypto_aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                                  const unsigned char *key,
                                  unsigned char *output, unsigned char *tag);
extern int crypto_aes_gcm_decrypt(const unsigned char *input, int input_len,
                                  const unsigned char *key,
                                  unsigned char *output, unsigned char *tag);

void hub_client_connect(bot_state_t *state);
void hub_client_disconnect(bot_state_t *state);

static hub_auth_state_t auth_state = HUB_AUTH_NONE;
static unsigned char challenge_received[32];
static time_t last_pong_sent = 0; // RATE LIMIT PONGS

void hub_client_init(bot_state_t *state) {
  state->hub_fd = -1;
  state->hub_connected = false;
  state->hub_connecting = false;
  state->hub_authenticated = false;
  state->last_hub_connect_attempt = 0;
  state->last_hub_ping_time = 0;
  state->last_hub_activity = 0;
  memset(state->hub_session_key, 0, 32);
  auth_state = HUB_AUTH_NONE;
  last_pong_sent = 0;
}

void hub_client_on_connect(bot_state_t *state) {
  if (state->hub_count > 0) {
    hub_client_connect(state);
  }
}

static int rsa_decrypt_with_bot_privkey(bot_state_t *state,
                                        const char *b64_priv_key,
                                        const unsigned char *enc_data,
                                        int enc_len, unsigned char *out_plain) {
  if (!b64_priv_key || !enc_data)
    return -1;

  // Decode BASE64 to get full PEM (with headers)
  int pem_len = 0;
  unsigned char *pem_data = base64_decode(b64_priv_key, &pem_len);
  if (!pem_data) {
    log_message(L_INFO, state, "[HUB] Base64 decode failed\n");
    return -1;
  }

  // Load PEM directly (includes headers)
  BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
  EVP_PKEY *priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  free(pem_data);

  if (!priv_key) {
    log_message(L_INFO, state, "[HUB] Failed to load private key\n");
    return -1;
  }

  // Perform RSA decryption
  int res = -1;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);

  if (ctx) {
    if (EVP_PKEY_decrypt_init(ctx) > 0) {
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

      size_t out_len;
      if (EVP_PKEY_decrypt(ctx, NULL, &out_len, enc_data, (size_t)enc_len) >
          0) {
        if (out_len <= 256) {
          if (EVP_PKEY_decrypt(ctx, out_plain, &out_len, enc_data,
                               (size_t)enc_len) > 0) {
            res = (int)out_len;
          } else {
            log_message(L_INFO, state, "[HUB] Decryption failed\n");
          }
        }
      }
    }
    EVP_PKEY_CTX_free(ctx);
  }

  EVP_PKEY_free(priv_key);
  return res;
}

static int rsa_sign_with_bot_privkey(bot_state_t *state,
                                     const char *b64_priv_key,
                                     const unsigned char *data, int data_len,
                                     unsigned char *sig_out) {
  if (!b64_priv_key || !data || !sig_out)
    return -1;
  int pem_len = 0;
  unsigned char *pem_data = base64_decode(b64_priv_key, &pem_len);
  if (!pem_data) {
    log_message(L_INFO, state, "[HUB] Base64 decode failed in signing\n");
    return -1;
  }
  BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
  EVP_PKEY *priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  free(pem_data);
  if (!priv_key) {
    log_message(L_INFO, state,
                "[HUB] Failed to load private key for signing\n");
    return -1;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(priv_key);
    return -1;
  }
  size_t sig_len = 512;
  int res = -1;
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv_key) > 0) {
    if (EVP_DigestSignUpdate(ctx, data, data_len) > 0) {
      if (EVP_DigestSignFinal(ctx, sig_out, &sig_len) > 0) {
        res = (int)sig_len;
      }
    }
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(priv_key);
  if (res < 0) {
    log_message(L_INFO, state, "[HUB] Signature calculation failed\n");
  }
  return res;
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
    if (send(state->hub_fd, buffer, 4 + enc_len + GCM_TAG_LEN, 0) <= 0) {
      hub_client_disconnect(state);
    }
  }
}

void hub_client_sync_hostmask(bot_state_t *state) {
  // Don't sync if we don't have a hostmask yet
  if (state->actual_hostname[0] == '\0') {
    return;
  }
  // Don't sync if not hub-managed
  if (state->hub_count == 0 || state->hub_fd == -1 ||
      !state->hub_authenticated) {
    return;
  }

  log_message(L_DEBUG, state, "[DEBUG] Syncing hostmask to hub: %s\n",
              state->actual_hostname);

  // Use standard config push which includes 'h' lines
  hub_client_push_config(state);
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
      written = snprintf(buffer + offset, max_len - offset, "c|%s|%s|%s|%ld\n",
                         c->name, c->key, op, (long)c->timestamp);
    } else {
      written = snprintf(buffer + offset, max_len - offset, "c|%s||%s|%ld\n",
                         c->name, op, (long)c->timestamp);
    }
    if (written < 0 || written >= max_len - offset)
      break;
    offset += written;
  }

  // Admin masks
  for (int i = 0; i < state->mask_count; i++) {
    const char *op = state->auth_masks[i].is_managed ? "add" : "del";
    written = snprintf(buffer + offset, max_len - offset, "m|%s|%s|%ld\n",
                       state->auth_masks[i].mask, op,
                       (long)state->auth_masks[i].timestamp);
    if (written < 0 || written >= max_len - offset)
      break;
    offset += written;
  }

  // Operator masks
  for (int i = 0; i < state->op_mask_count; i++) {
    const char *op = state->op_masks[i].is_managed ? "add" : "del";
    written = snprintf(buffer + offset, max_len - offset, "o|%s|%s|%s|%ld\n",
                       state->op_masks[i].mask, state->op_masks[i].password, op,
                       (long)state->op_masks[i].timestamp);
    if (written < 0 || written >= max_len - offset)
      break;
    offset += written;
  }

  // Admin password (with timestamp for conflict resolution)
  if (state->bot_pass[0] != '\0') {
    written = snprintf(buffer + offset, max_len - offset, "a|%s|%ld\n",
                       state->bot_pass, (long)state->bot_pass_ts);
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
  }

  // Bot password (with timestamp for conflict resolution)
  if (state->bot_comm_pass[0] != '\0') {
    written = snprintf(buffer + offset, max_len - offset, "p|%s|%ld\n",
                       state->bot_comm_pass, (long)state->bot_comm_pass_ts);
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
  }

  // Hostmask
  if (state->actual_hostname[0] != '\0') {
    written = snprintf(buffer + offset, max_len - offset, "h|%s|%ld\n",
                       state->actual_hostname, (long)time(NULL));
    if (written > 0 && written < max_len - offset) {
      offset += written;
    }
  }

  // Nick
  if (state->current_nick[0] != '\0') {
    written = snprintf(buffer + offset, max_len - offset, "n|%s|%ld\n",
                       state->current_nick, (long)time(NULL));
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

    if (send(state->hub_fd, cipher, 4 + cipher_len + GCM_TAG_LEN, 0) > 0) {
      return true; // Request sent successfully
    }
  }

  return false; // Failed to send, use PRIVMSG fallback
}

// Alias for promoting local config to hub (e.g. on connect)
void hub_client_promote_local_config(bot_state_t *state) {
  hub_client_push_config(state);
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

    if (send(state->hub_fd, cipher, 4 + cipher_len + GCM_TAG_LEN, 0) > 0) {
      log_message(L_INFO, state, "[HUB] Config pushed to hub\n");
    } else {
      log_message(L_INFO, state, "[HUB] Failed to push config\n");
      hub_client_disconnect(state);
    }
  }
}

void hub_client_process_config_data(bot_state_t *state, const char *payload) {
  log_message(L_DEBUG, state, "[HUB-SYNC] Processing config data from hub\n");

  char work_buf[MAX_BUFFER];
  strncpy(work_buf, payload, sizeof(work_buf) - 1);
  work_buf[sizeof(work_buf) - 1] = '\0';

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

      // Try with key
      parsed = sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%ld", chan, key, op, &ts);
      if (parsed < 3) {
        // Try without key
        parsed = sscanf(data, "%64[^|]||%7[^|]|%ld", chan, op, &ts);
        key[0] = '\0';
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

    case 'm': // Admin mask
    {
      char mask[MAX_MASK_LEN], op[8];
      long ts;
      if (sscanf(data, "%127[^|]|%7[^|]|%ld", mask, op, &ts) == 3) {
        bool is_add = (strcmp(op, "add") == 0);

        // Find existing
        int idx = -1;
        for (int i = 0; i < state->mask_count; i++) {
          if (strcmp(state->auth_masks[i].mask, mask) == 0) {
            idx = i;
            break;
          }
        }

        log_message(L_DEBUG, state, "[HUB-SYNC] Mask %s: hub_ts=%ld local_ts=%ld op=%s\n",
                    mask, ts, idx >= 0 ? (long)state->auth_masks[idx].timestamp : 0, op);

        if (idx == -1 && is_add) {
          // New mask from hub
          if (state->mask_count < MAX_MASKS) {
            size_t mask_len = strlen(mask);
            if (mask_len >= MAX_MASK_LEN)
              mask_len = MAX_MASK_LEN - 1;
            memcpy(state->auth_masks[state->mask_count].mask, mask, mask_len);
            state->auth_masks[state->mask_count].mask[mask_len] = '\0';
            state->auth_masks[state->mask_count].is_managed = true;
            state->auth_masks[state->mask_count].timestamp = ts;
            state->mask_count++;
            updates++;
            log_message(L_INFO, state, "[HUB] Added admin mask: %s\n", mask);
          }
        } else if (idx != -1) {
          // Compare timestamps
          if (ts > state->auth_masks[idx].timestamp) {
            state->auth_masks[idx].is_managed = is_add;
            state->auth_masks[idx].timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Updated admin mask: %s (%s)\n",
                        mask, op);
          } else {
            log_message(L_DEBUG, state, "[HUB-SYNC] Rejected mask %s: hub_ts=%ld <= local_ts=%ld\n",
                        mask, ts, (long)state->auth_masks[idx].timestamp);
          }
        }
      }
    } break;

    case 'o': // Oper mask
    {
      char mask[MAX_MASK_LEN], pass[MAX_PASS], op[8];
      long ts;
      if (sscanf(data, "%127[^|]|%127[^|]|%7[^|]|%ld", mask, pass, op, &ts) ==
          4) {
        bool is_add = (strcmp(op, "add") == 0);

        int idx = -1;
        for (int i = 0; i < state->op_mask_count; i++) {
          if (strcmp(state->op_masks[i].mask, mask) == 0) {
            idx = i;
            break;
          }
        }

        log_message(L_DEBUG, state, "[HUB-SYNC] Oper %s: hub_ts=%ld local_ts=%ld op=%s idx=%d\n",
                    mask, ts, idx >= 0 ? (long)state->op_masks[idx].timestamp : 0, op, idx);

        if (idx == -1 && is_add) {
          if (state->op_mask_count < MAX_OP_MASKS) {
            size_t mask_len = strlen(mask);
            if (mask_len >= MAX_MASK_LEN)
              mask_len = MAX_MASK_LEN - 1;
            memcpy(state->op_masks[state->op_mask_count].mask, mask, mask_len);
            state->op_masks[state->op_mask_count].mask[mask_len] = '\0';

            size_t pass_len = strlen(pass);
            if (pass_len >= MAX_PASS)
              pass_len = MAX_PASS - 1;
            memcpy(state->op_masks[state->op_mask_count].password, pass,
                   pass_len);
            state->op_masks[state->op_mask_count].password[pass_len] = '\0';
            state->op_masks[state->op_mask_count].is_managed = true;
            state->op_masks[state->op_mask_count].timestamp = ts;
            state->op_mask_count++;
            updates++;
            log_message(L_INFO, state, "[HUB] Added oper mask: %s\n", mask);
          } else {
            log_message(L_DEBUG, state, "[HUB-SYNC] Rejected oper %s: max masks reached\n", mask);
          }
        } else if (idx != -1) {
          if (ts > state->op_masks[idx].timestamp) {
            size_t pass_len = strlen(pass);
            if (pass_len >= MAX_PASS)
              pass_len = MAX_PASS - 1;
            memcpy(state->op_masks[idx].password, pass, pass_len);
            state->op_masks[idx].password[pass_len] = '\0';
            state->op_masks[idx].is_managed = is_add;
            state->op_masks[idx].timestamp = ts;
            updates++;
            log_message(L_INFO, state, "[HUB] Updated oper mask: %s (%s)\n",
                        mask, op);
          } else {
            log_message(L_DEBUG, state, "[HUB-SYNC] Rejected oper %s: hub_ts=%ld <= local_ts=%ld\n",
                        mask, ts, (long)state->op_masks[idx].timestamp);
          }
        } else if (idx == -1 && !is_add) {
          log_message(L_DEBUG, state, "[HUB-SYNC] Skipped oper del for non-existent: %s\n", mask);
        }
      }
    } break;

    case 'a': // Admin password: a|password|timestamp
    {
      // Hub sends: a|password|timestamp
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        // Fallback: treat entire data as password
        strncpy(pass, data, MAX_PASS - 1);
        pass[MAX_PASS - 1] = '\0';
        ts = 0;
      }

      log_message(L_DEBUG, state, "[HUB-SYNC] AdminPass: hub_ts=%ld local_ts=%ld\n",
                  ts, (long)state->bot_pass_ts);

      // Only update if hub has newer timestamp
      if (ts > state->bot_pass_ts || state->bot_pass[0] == '\0') {
        strncpy(state->bot_pass, pass, MAX_PASS - 1);
        state->bot_pass[MAX_PASS - 1] = '\0';
        state->bot_pass_ts = ts;
        updates++;
        log_message(L_INFO, state, "[HUB] Updated admin password (ts=%ld)\n",
                    ts);
      } else {
        log_message(L_DEBUG, state, "[HUB-SYNC] Rejected admin password: hub_ts=%ld <= local_ts=%ld\n",
                    ts, (long)state->bot_pass_ts);
      }
    } break;

    case 'p': // Bot password: p|password|timestamp
    {
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        strncpy(pass, data, MAX_PASS - 1);
        pass[MAX_PASS - 1] = '\0';
        ts = 0;
      }
      log_message(L_DEBUG, state, "[HUB-SYNC] BotPass: hub_ts=%ld local_ts=%ld\n",
                  ts, (long)state->bot_comm_pass_ts);
      // Only update if hub has newer timestamp
      if (ts > state->bot_comm_pass_ts || state->bot_comm_pass[0] == '\0') {
        strncpy(state->bot_comm_pass, pass, MAX_PASS - 1);
        state->bot_comm_pass[MAX_PASS - 1] = '\0';
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
      // Format: hostmask|uuid|timestamp
      char hostmask[MAX_MASK_LEN];
      char uuid[64];
      long ts = 0;
      hostmask[0] = '\0';
      uuid[0] = '\0';

      log_message(L_DEBUG, state, "[HUB-SYNC] Processing bot line\n");

      // Parse broadcast format: b|hostmask|uuid|timestamp
      int parsed = sscanf(data, "%127[^|]|%63[^|]|%ld", hostmask, uuid, &ts);
      log_message(L_DEBUG, state,
                  "[HUB-SYNC] Parsed %d fields: hostmask='%s' uuid='%s' ts=%ld\n",
                  parsed, hostmask, uuid, ts);
      if (parsed < 1) {
        // Fallback: treat entire data as hostmask
        strncpy(hostmask, data, MAX_MASK_LEN - 1);
        hostmask[MAX_MASK_LEN - 1] = '\0';
      }

      if (hostmask[0] != '\0') {
        // Check if already exists (by hostmask only)
        int existing_idx = -1;
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char existing_mask[MAX_MASK_LEN];
          if (sscanf(state->trusted_bots[i], "%127[^|]", existing_mask) >= 1) {
            if (strcmp(existing_mask, hostmask) == 0) {
              existing_idx = i;
              break;
            }
          }
        }

        if (existing_idx != -1) {
          // Check if update is newer
          long old_ts = 0;
          sscanf(state->trusted_bots[existing_idx], "%*[^|]|%*[^|]|%ld",
                 &old_ts);
          if (ts > old_ts) {
            char full_entry[256];
            snprintf(full_entry, sizeof(full_entry), "%s|%s|%ld", hostmask,
                     uuid, ts);
            free(state->trusted_bots[existing_idx]);
            state->trusted_bots[existing_idx] = strdup(full_entry);
            updates++;
            log_message(L_INFO, state, "[HUB] Updated trusted bot: %s\n",
                        hostmask);
          }
        } else if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
          // New Add
          char full_entry[256];
          snprintf(full_entry, sizeof(full_entry), "%s|%s|%ld", hostmask, uuid,
                   ts);
          state->trusted_bots[state->trusted_bot_count++] = strdup(full_entry);
          updates++;
          log_message(L_INFO, state, "[HUB] Added trusted bot: %s\n", hostmask);
        }
      }
    } break;

    case 'P': // PURGE command
    {
      // Format: PURGE|immediate|timestamp or PURGE|30|timestamp
      char param[32];
      long ts;
      if (sscanf(data, "URGE|%31[^|]|%ld", param, &ts) == 2) {
        bool immediate = (strcmp(param, "immediate") == 0);
        int days = immediate ? 0 : atoi(param);
        if (days < 0) days = 30;

        time_t cutoff = ts - (days * 24 * 60 * 60);
        int purged = 0;

        // Purge channels with is_managed=false and old timestamp
        chan_t *c = state->chanlist;
        while (c) {
          chan_t *next = c->next;
          if (!c->is_managed && (immediate || c->timestamp < cutoff)) {
            channel_remove(state, c->name);
            purged++;
          }
          c = next;
        }

        // Purge admin masks
        for (int i = 0; i < state->mask_count; i++) {
          if (!state->auth_masks[i].is_managed &&
              (immediate || state->auth_masks[i].timestamp < cutoff)) {
            memmove(&state->auth_masks[i], &state->auth_masks[i+1],
                    (state->mask_count - i - 1) * sizeof(admin_entry_t));
            state->mask_count--;
            purged++;
            i--;
          }
        }

        // Purge oper masks
        for (int i = 0; i < state->op_mask_count; i++) {
          if (!state->op_masks[i].is_managed &&
              (immediate || state->op_masks[i].timestamp < cutoff)) {
            memmove(&state->op_masks[i], &state->op_masks[i+1],
                    (state->op_mask_count - i - 1) * sizeof(op_entry_t));
            state->op_mask_count--;
            purged++;
            i--;
          }
        }

        if (purged > 0) {
          log_message(L_INFO, state, "[HUB] Purged %d tombstoned entries\n", purged);
          config_write(state, state->startup_password);
        }
      }
    } break;

    default:
      log_message(L_DEBUG, state, "[HUB-SYNC] Unrecognized line type '%c': %s\n", type, line);
      break;
    }

    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (updates > 0) {
    log_message(L_INFO, state, "[HUB] Applied %d config updates from hub\n",
                updates);
    log_message(L_DEBUG, state, "[HUB-SYNC] Saving config (will trigger push back to hub)\n");
    config_write(state, state->startup_password);
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

      // Update the hub_key in memory
      if (payload_len < MAX_HUB_KEY_SIZE) {
        memset(state->hub_key, 0, sizeof(state->hub_key));
        memcpy(state->hub_key, payload, payload_len);
        state->hub_key[payload_len] = '\0';

        log_message(L_INFO, state, "[HUB] Updated hub private key in memory\n");

        // Save the new key to config file immediately
        if (strlen(state->startup_password) > 0) {
          config_write(state, state->startup_password);
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
                    "[HUB] ERROR: New key too large (%d bytes, max %d)\n",
                    payload_len, MAX_HUB_KEY_SIZE);
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
        strncpy(nick, hostmask, MAX_NICK - 1);
        nick[MAX_NICK - 1] = '\0';
      }

      // Check if we're in that channel and have ops
      chan_t *c = channel_find(state, channel);
      if (c && c->status == C_IN) {
        bool am_i_opped = false;
        for (int i = 0; i < c->roster_count; i++) {
          if (strcasecmp(c->roster[i].nick, state->current_nick) == 0 &&
              c->roster[i].is_op) {
            am_i_opped = true;
            break;
          }
        }

        if (am_i_opped) {
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
    // Trigger fallback to PRIVMSG method
    // The channel manager will retry via PRIVMSG on next cycle
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

  // RSA-2048 private key in base64 PEM format should be ~1600-1800 chars
  size_t key_len = strlen(state->hub_key);
  if (key_len < 1400 || key_len > 2300) {
    log_message(L_INFO, state,
                "[HUB] Cannot connect: Hub key length suspicious (%zu chars). "
                "Expected 1400-2300. Key may be truncated/corrupted. Use "
                "'sethubkey' multipart mode.\n",
                key_len);
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
  strncpy(hub_original, hub_tmp, sizeof(hub_original) - 1);
  hub_original[sizeof(hub_original) - 1] = '\0';
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
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, hub_tmp, &addr.sin_addr);
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sockfd);
    state->hub_connecting = false;
    __sync_lock_release(&lock);
    return;
  }
  state->hub_fd = sockfd;
  state->hub_connected = true;
  state->hub_authenticated = false;
  auth_state = HUB_AUTH_NONE;
  // Store which hub we connected to (after successful connection)
  strncpy(state->current_hub, hub_original, sizeof(state->current_hub) - 1);
  state->current_hub[sizeof(state->current_hub) - 1] = '\0';
  int uuid_len = strlen(state->bot_uuid);
  uint32_t net_len = htonl(uuid_len);
  if (send(state->hub_fd, &net_len, 4, 0) == 4 &&
      send(state->hub_fd, state->bot_uuid, uuid_len, 0) == uuid_len) {
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
  int n = recv(state->hub_fd, header, 4, 0);

  if (n <= 0) {
    hub_client_disconnect(state);
    return;
  }
  if (n != 4) {
    hub_client_disconnect(state);
    return;
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
      free(packet_body);
      hub_client_disconnect(state);
      return;
    }
    total_read += r;
  }
  if (!state->hub_authenticated) {
    if (auth_state == HUB_AUTH_SENT_UUID) {
      unsigned char challenge[32];
      if (rsa_decrypt_with_bot_privkey(state, state->hub_key, packet_body,
                                       packet_len, challenge) == 32) {
        memcpy(challenge_received, challenge, 32);
        unsigned char signature[512];
        int sig_len = rsa_sign_with_bot_privkey(state, state->hub_key,
                                                challenge, 32, signature);
        if (sig_len > 0) {
          uint32_t sig_net_len = htonl(sig_len);
          if (send(state->hub_fd, &sig_net_len, 4, 0) == 4 &&
              send(state->hub_fd, signature, sig_len, 0) == sig_len) {
            auth_state = HUB_AUTH_SENT_SIGNATURE;
            log_message(L_INFO, state, "[HUB] Signature sent.\n");
          } else {
            log_message(L_INFO, state, "[HUB] Failed to send signature\n");
            free(packet_body);
            hub_client_disconnect(state);
            return;
          }
        } else {
          log_message(L_INFO, state,
                      "[HUB] Failed to sign challenge (Key mismatch?)\n");
          free(packet_body);
          hub_client_disconnect(state);
          return;
        }
      } else {
        log_message(L_INFO, state,
                    "[HUB] Failed to decrypt challenge (Incorrect Key?)\n");
        free(packet_body);
        hub_client_disconnect(state);
        return;
      }
    } else if (auth_state == HUB_AUTH_SENT_SIGNATURE) {
      unsigned char session_key[32];
      if (rsa_decrypt_with_bot_privkey(state, state->hub_key, packet_body,
                                       packet_len, session_key) == 32) {
        memcpy(state->hub_session_key, session_key, 32);
        state->hub_authenticated = true;
        auth_state = HUB_AUTH_COMPLETE;
        state->last_hub_activity = time(NULL);
        log_message(L_INFO, state, "[HUB] Authenticated!\n");
        hub_client_push_config(state);
      } else {
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
            send(state->hub_fd, pong_buf, 4 + pong_enc + GCM_TAG_LEN, 0);
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
