#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

void bot_comms_process_payload(bot_state_t *state, const char *payload) {
  if (!payload || state->bot_comm_pass[0] == '\0') return;

  char msg_copy[MAX_BUFFER];
  snprintf(msg_copy, sizeof(msg_copy), "%s", payload);

  char *saveptr_enc;
  char *encoded_ciphertext = strtok_r(msg_copy, ":", &saveptr_enc);
  char *encoded_tag_str = strtok_r(NULL, "", &saveptr_enc);
  if (!encoded_ciphertext || !encoded_tag_str) return;

  int decoded_len = 0, tag_len = 0;
  unsigned char *decoded_data = base64_decode(encoded_ciphertext, &decoded_len);
  unsigned char *tag = base64_decode(encoded_tag_str, &tag_len);

  if (!decoded_data || !tag || decoded_len <= (SALT_SIZE + GCM_IV_LEN) ||
      tag_len != GCM_TAG_LEN) {
    free(decoded_data);
    free(tag);
    return;
  }

  unsigned char salt[SALT_SIZE];
  memcpy(salt, decoded_data, SALT_SIZE);
  unsigned char key[32];
  EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                 (const unsigned char *)state->bot_comm_pass,
                 strlen(state->bot_comm_pass), 1, key, NULL);

  int ciphertext_len = decoded_len - SALT_SIZE;
  unsigned char *decrypted_data = malloc(ciphertext_len + 1);
  if (decrypted_data) {
    int decrypted_len = crypto_aes_gcm_decrypt(decoded_data + SALT_SIZE,
                                               ciphertext_len, key,
                                               decrypted_data, tag);
    if (decrypted_len >= 0) {
      decrypted_data[decrypted_len] = '\0';
      char *saveptr_bot;
      char *ts_str  = strtok_r((char *)decrypted_data, ":", &saveptr_bot);
      char *non_str = strtok_r(NULL, ":", &saveptr_bot);
      char *cmd_str = strtok_r(NULL, "", &saveptr_bot);
      if (ts_str && non_str && cmd_str) {
        time_t received_time = atol(ts_str);
        uint64_t received_nonce = strtoull(non_str, NULL, 10);
        if (fabs(difftime(time(NULL), received_time)) <= 60) {
          bool nonce_is_reused = false;
          for (int i = 0; i < NONCE_CACHE_SIZE; i++) {
            if (state->recent_nonces[i] == received_nonce) {
              nonce_is_reused = true;
              break;
            }
          }
          if (!nonce_is_reused) {
            state->recent_nonces[state->nonce_idx] = received_nonce;
            state->nonce_idx = (state->nonce_idx + 1) % NONCE_CACHE_SIZE;
            char *saveptr_cmd;
            char *bot_command = strtok_r(cmd_str, " ", &saveptr_cmd);
            char *bot_arg1    = strtok_r(NULL, " ", &saveptr_cmd);
            if (bot_command && strcasecmp(bot_command, "SETNICK") == 0 && bot_arg1) {
              if (is_valid_bot_nick(bot_arg1)) {
                snprintf(state->target_nick, MAX_NICK, "%s", bot_arg1);
                state->current_nick_ts = time(NULL);
                hub_client_push_delta(state, "n", bot_arg1, state->current_nick_ts);
                config_write_with_state_pass(state);
              }
            } else if (bot_command && strcasecmp(bot_command, "INVITE") == 0 && bot_arg1) {
              char *bot_arg2 = strtok_r(NULL, " ", &saveptr_cmd);
              if (bot_arg2) {
                chan_t *ic = channel_find(state, bot_arg1);
                if (ic && ic->status == C_IN) {
                  bool have_ops = false;
                  for (int r = 0; r < ic->roster_count; r++) {
                    if (strcasecmp(ic->roster[r].nick, state->current_nick) == 0 &&
                        ic->roster[r].is_op) {
                      have_ops = true;
                      break;
                    }
                  }
                  if (have_ops)
                    irc_printf(state, "INVITE %s %s\r\n", bot_arg2, bot_arg1);
                }
              }
            }
          }
        }
      }
    }
    free(decrypted_data);
  }
  free(decoded_data);
  free(tag);
}

void bot_comms_send_command(bot_state_t *state, const char *target_nick,
                            const char *format, ...) {
  if (!target_nick || !format) {
    log_message(L_DEBUG, state,
                "[BOT-COMM] Cannot send: target_nick=%p format=%p\n",
                (void *)target_nick, (void *)format);
    return;
  }
  if (state->bot_comm_pass[0] == '\0') {
    log_message(L_DEBUG, state,
                "[BOT-COMM] Cannot send to %s: bot_comm_pass is empty\n",
                target_nick);
    return;
  }

  char command_part[256];
  va_list args;
  va_start(args, format);
  int vn = vsnprintf(command_part, sizeof(command_part), format, args);
  va_end(args);
  if (vn < 0) return;

  char plaintext_message[512];
  time_t current_time = time(NULL);
  uint64_t nonce;
  if (RAND_bytes((unsigned char *)&nonce, sizeof(nonce)) != 1) return;

  snprintf(plaintext_message, sizeof(plaintext_message), "%ld:%llu:%s",
           current_time, (unsigned long long)nonce, command_part);

  unsigned char salt[SALT_SIZE];
  if (RAND_bytes(salt, sizeof(salt)) != 1) return;

  unsigned char key[32];
  EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                 (const unsigned char *)state->bot_comm_pass,
                 strlen(state->bot_comm_pass), 1, key, NULL);

  int plaintext_len = strlen(plaintext_message);

  unsigned char ciphertext[SALT_SIZE + GCM_IV_LEN + 512 + 32];
  unsigned char tag[GCM_TAG_LEN];

  int encrypted_len =
      crypto_aes_gcm_encrypt((unsigned char *)plaintext_message, plaintext_len,
                             key, ciphertext + SALT_SIZE, tag);

  if (encrypted_len > 0) {
    memcpy(ciphertext, salt, SALT_SIZE);

    int total_len = SALT_SIZE + encrypted_len;

    char *encoded_ciphertext = base64_encode(ciphertext, total_len);
    char *encoded_tag = base64_encode(tag, GCM_TAG_LEN);

    if (encoded_ciphertext && encoded_tag) {
      /* Route through hub if connected; PRIVMSG is fallback for hub-less bots */
      bool sent_via_hub = false;
      if (state->hub_connected && state->hub_authenticated &&
          state->hub_fd != -1) {
        char target_uuid[64] = "";
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char bnick[MAX_NICK] = "";
          char bmask[MAX_MASK_LEN] = "";
          sscanf(state->trusted_bots[i], "%9[^!]", bnick);
          if (strcasecmp(bnick, target_nick) != 0) continue;
          sscanf(state->trusted_bots[i], "%255[^|]|%63[^|]", bmask, target_uuid);
          break;
        }
        if (target_uuid[0] != '\0') {
          log_message(L_DEBUG, state,
                      "[BOT-COMM] Relaying %s to %s via hub\n",
                      command_part, target_nick);
          sent_via_hub = hub_client_relay_bot_command(state, target_uuid,
                                                      encoded_ciphertext,
                                                      encoded_tag);
        }
      }
      if (!sent_via_hub) {
        log_message(L_DEBUG, state,
                    "[BOT-COMM] Sending encrypted PRIVMSG to %s: %s\n",
                    target_nick, command_part);
        irc_printf(state, "PRIVMSG %s :%s:%s\r\n", target_nick,
                   encoded_ciphertext, encoded_tag);
      }
    }

    free(encoded_ciphertext);
    free(encoded_tag);
  }
}
