#include <ctype.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message) {
  if (strcasecmp(dest, state->current_nick) != 0)
    return;

  char user_host[256];
  snprintf(user_host, sizeof(user_host), "%s!%s@%s", nick, user, host);

  log_message(L_MSG, state, "[MSG] (%s): %s\n", user_host, message);

  /* --- Block 1: Trusted Bot Logic (Encrypted Communication) --- */

  if (auth_is_trusted_bot(state, user_host)) {
    char message_copy_bot[MAX_BUFFER];
    snprintf(message_copy_bot, sizeof(message_copy_bot), "%s", message);

    char *saveptr_enc;
    char *encoded_ciphertext = strtok_r(message_copy_bot, ":", &saveptr_enc);
    char *encoded_tag = strtok_r(NULL, "", &saveptr_enc);

    if (encoded_ciphertext && encoded_tag) {
      unsigned char *decoded_data = NULL;
      unsigned char *tag = NULL;
      int decoded_len = 0;
      int tag_len = 0;

      decoded_data = base64_decode(encoded_ciphertext, &decoded_len);
      tag = base64_decode(encoded_tag, &tag_len);

      if (decoded_data && tag && decoded_len > (SALT_SIZE + GCM_IV_LEN) &&
          tag_len == GCM_TAG_LEN) {
        unsigned char salt[SALT_SIZE];
        memcpy(salt, decoded_data, SALT_SIZE);

        unsigned char key[32];
        if (!crypto_derive_config_key(state->bot_comm_pass, salt, key)) {
          if (decoded_data) free(decoded_data);
          if (tag) free(tag);
          return;
        }

        unsigned char *ciphertext_ptr = decoded_data + SALT_SIZE;
        int ciphertext_len = decoded_len - SALT_SIZE;

        unsigned char *decrypted_data = malloc(ciphertext_len + 1);
        if (decrypted_data) {
          int decrypted_len = crypto_aes_gcm_decrypt(
              ciphertext_ptr, ciphertext_len, key, decrypted_data, tag);

          /* Legacy-format fallback for un-migrated peer bots. */
          if (decrypted_len < 0 &&
              crypto_derive_legacy_key(state->bot_comm_pass, salt, key)) {
            decrypted_len = crypto_aes_gcm_decrypt(
                ciphertext_ptr, ciphertext_len, key, decrypted_data, tag);
          }

          if (decrypted_len >= 0) {
            decrypted_data[decrypted_len] = '\0';

            char *saveptr_bot;
            char *received_timestamp_str =
                strtok_r((char *)decrypted_data, ":", &saveptr_bot);
            char *received_nonce_str = strtok_r(NULL, ":", &saveptr_bot);
            char *command_part = strtok_r(NULL, "", &saveptr_bot);

            if (received_timestamp_str && received_nonce_str && command_part) {
              time_t received_time = atol(received_timestamp_str);
              uint64_t received_nonce = strtoull(received_nonce_str, NULL, 10);

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
                  char *bot_command = strtok_r(command_part, " ", &saveptr_cmd);
                  char *bot_arg1 = strtok_r(NULL, " ", &saveptr_cmd);
                  if (bot_command && strcasecmp(bot_command, "OPME") == 0 &&
                      bot_arg1) {
                    irc_printf(state, "MODE %s +o %s\r\n", bot_arg1, nick);
                  } else if (bot_command &&
                             strcasecmp(bot_command, "SETNICK") == 0 &&
                             bot_arg1) {
                    if (is_valid_bot_nick(bot_arg1)) {
                      snprintf(state->target_nick, MAX_NICK, "%s", bot_arg1);
                      state->current_nick_ts = time(NULL);
                      hub_client_push_delta(state, "n", bot_arg1,
                                            state->current_nick_ts);
                      config_write_with_state_pass(state);
                    }
                  } else if (bot_command &&
                             strcasecmp(bot_command, "INVITE") == 0 &&
                             bot_arg1) {
                    char *bot_arg2 = strtok_r(NULL, " ", &saveptr_cmd);
                    if (bot_arg2) {
                      chan_t *ic = channel_find(state, bot_arg1);
                      if (ic && ic->status == C_IN) {
                        bool have_ops = false;
                        for (int r = 0; r < ic->roster_count; r++) {
                          if (strcasecmp(ic->roster[r].nick,
                                         state->current_nick) == 0 &&
                              ic->roster[r].is_op) {
                            have_ops = true;
                            break;
                          }
                        }
                        if (have_ops) {
                          log_message(L_INFO, state,
                                      "[BOT-COMMS] Inviting %s to %s (bot req)\n",
                                      bot_arg2, bot_arg1);
                          irc_printf(state, "INVITE %s %s\r\n",
                                     bot_arg2, bot_arg1);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          secure_wipe(decrypted_data, (size_t)ciphertext_len + 1);
          free(decrypted_data);
        }
        secure_wipe(key, sizeof(key));
      }

      if (decoded_data)
        free(decoded_data);
      if (tag)
        free(tag);
    }
  }
  /* --- Block 2: Admin/Op Logic --- */
  /* Two accepted formats:
   *   v1 (new, default):   "~A1 <base64-blob>"
   *     blob = salt(16) || iv(12) || ciphertext(N) || tag(16)
   *     key  = PBKDF2-HMAC-SHA256(admin_password, salt, PBKDF2_ITERATIONS, 32)
   *     plaintext = "<timestamp>:<nonce>:<command> [args...]"
   *   legacy (deprecated): "<nonce>:<hash> <command> [args...]"
   *     hash = sha256(password ":" minute ":" nonce)
   *
   * Both formats end up populating the same dispatch variables and fall
   * through to the existing command tree below. */

  char message_copy[MAX_BUFFER];     /* legacy parser working buffer */
  char v1_plaintext[MAX_BUFFER];     /* v1 decrypted-payload working buffer */
  bool used_v1 = false;
  bool is_admin = false;
  bool is_op = false;
  user_record_t *auth_user = NULL;
  char *command = NULL, *arg1 = NULL, *arg2 = NULL, *arg3 = NULL;
  uint64_t nonce_val = 0;

  if (strncmp(message, "~A1 ", 4) == 0) {
    /* ---- v1: AES-256-GCM-protected admin command ---- */
    used_v1 = true;
    const char *b64 = message + 4;
    int blob_len = 0;
    unsigned char *blob = base64_decode(b64, &blob_len);
    if (!blob || blob_len < (int)(SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN)) {
      if (blob) { secure_wipe(blob, (size_t)(blob_len > 0 ? blob_len : 0)); free(blob); }
      log_message(L_CMD, state,
                  "[CMD] v1 auth: malformed blob from %s\n", user_host);
      return;
    }
    int ct_len = blob_len - (int)SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;
    if (ct_len <= 0) {
      secure_wipe(blob, (size_t)blob_len);
      free(blob);
      return;
    }

    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    memcpy(salt, blob, SALT_SIZE);
    memcpy(iv,   blob + SALT_SIZE, GCM_IV_LEN);
    memcpy(tag,  blob + blob_len - GCM_TAG_LEN, GCM_TAG_LEN);

    /* Identify the sender by hostmask BEFORE trusting any payload content.
     * auth_find_user updates last_seen/last_used and sets config_dirty even
     * on the v1 path, so the hub stays in sync. */
    time_t now_auth = time(NULL);
    user_record_t *candidate = auth_find_user(state, user_host, now_auth);
    if (!candidate || !candidate->is_active || candidate->password[0] == '\0') {
      log_message(L_CMD, state,
                  "[CMD] v1 auth: no matching active user for %s\n", user_host);
      secure_wipe(blob, (size_t)blob_len);
      free(blob);
      return;
    }

    unsigned char key[32];
    if (!crypto_derive_config_key(candidate->password, salt, key)) {
      log_message(L_CMD, state, "[CMD] v1 auth: PBKDF2 failed\n");
      secure_wipe(blob, (size_t)blob_len);
      free(blob);
      return;
    }

    /* crypto_aes_gcm_decrypt expects input = iv || ciphertext, plus tag. */
    int gcm_in_len = GCM_IV_LEN + ct_len;
    unsigned char *gcm_in = malloc((size_t)gcm_in_len);
    if (!gcm_in) {
      secure_wipe(key, sizeof(key));
      secure_wipe(blob, (size_t)blob_len);
      free(blob);
      return;
    }
    memcpy(gcm_in,              iv,                 GCM_IV_LEN);
    memcpy(gcm_in + GCM_IV_LEN, blob + SALT_SIZE + GCM_IV_LEN, (size_t)ct_len);

    unsigned char *plain = malloc((size_t)ct_len + 1);
    if (!plain) {
      secure_wipe(key, sizeof(key));
      secure_wipe(gcm_in, (size_t)gcm_in_len);
      free(gcm_in);
      secure_wipe(blob, (size_t)blob_len);
      free(blob);
      return;
    }
    int plain_len = crypto_aes_gcm_decrypt(gcm_in, gcm_in_len, key, plain, tag);
    secure_wipe(key, sizeof(key));
    secure_wipe(gcm_in, (size_t)gcm_in_len);
    free(gcm_in);
    secure_wipe(blob, (size_t)blob_len);
    free(blob);

    if (plain_len < 0) {
      log_message(L_CMD, state,
                  "[CMD] v1 auth: GCM tag failed for %s (wrong password?)\n",
                  user_host);
      secure_wipe(plain, (size_t)ct_len + 1);
      free(plain);
      return;
    }
    plain[plain_len] = '\0';

    /* Copy decrypted plaintext to v1_plaintext so strtok_r pointers we save
     * remain valid for the dispatch below. */
    if ((size_t)plain_len >= sizeof(v1_plaintext)) {
      secure_wipe(plain, (size_t)plain_len);
      free(plain);
      return;
    }
    memcpy(v1_plaintext, plain, (size_t)plain_len);
    v1_plaintext[plain_len] = '\0';
    secure_wipe(plain, (size_t)plain_len);
    free(plain);

    /* Parse: timestamp:nonce:command args */
    char *sp_v1;
    char *ts_str    = strtok_r(v1_plaintext, ":", &sp_v1);
    char *nonce_str = strtok_r(NULL,         ":", &sp_v1);
    char *cmd_line  = strtok_r(NULL,         "",  &sp_v1);
    if (!ts_str || !nonce_str || !cmd_line) {
      log_message(L_CMD, state,
                  "[CMD] v1 auth: malformed plaintext (missing fields)\n");
      secure_wipe(v1_plaintext, sizeof(v1_plaintext));
      return;
    }

    /* Freshness window — narrower than legacy because the script doesn't
     * need clock-skew tolerance beyond a few seconds. */
    time_t client_ts = (time_t)strtoll(ts_str, NULL, 10);
    if (llabs((long long)(now_auth - client_ts)) > 30) {
      log_message(L_CMD, state,
                  "[CMD] v1 auth: timestamp skew %lds (max 30) from %s\n",
                  (long)(now_auth - client_ts), user_host);
      secure_wipe(v1_plaintext, sizeof(v1_plaintext));
      return;
    }

    /* Replay check against the shared admin_nonces ring. */
    nonce_val = strtoull(nonce_str, NULL, 10);
    bool replay_v1 = false;
    for (int _ri = 0; _ri < MAX_SEEN_HASHES; _ri++) {
      if (state->admin_nonces[_ri] == nonce_val) { replay_v1 = true; break; }
    }
    if (replay_v1) {
      log_message(L_CMD, state,
                  "[CMD] v1 auth: replay detected (nonce=%llu) from %s\n",
                  (unsigned long long)nonce_val, user_host);
      secure_wipe(v1_plaintext, sizeof(v1_plaintext));
      return;
    }
    state->admin_nonces[state->admin_nonce_idx] = nonce_val;
    state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;

    /* Tokenize the command line, in place, the same way the legacy path does. */
    char *sp_cmd;
    command = strtok_r(cmd_line, " ", &sp_cmd);
    arg1    = strtok_r(NULL,     " ", &sp_cmd);
    arg2    = strtok_r(NULL,     " ", &sp_cmd);
    arg3    = strtok_r(NULL,     " ", &sp_cmd);
    if (!command) {
      secure_wipe(v1_plaintext, sizeof(v1_plaintext));
      return;
    }

    auth_user = candidate;
    if (candidate->type == 'a') is_admin = true;
    if (candidate->type == 'o') is_op    = true;

    log_message(L_DEBUG, state,
                "[CMD_DEBUG] v1 Parsed: Cmd='%s' Arg1='%s' User='%s' Type=%c\n",
                command, (arg1 ? arg1 : "NULL"),
                candidate->name, candidate->type);
  } else {
    /* ---- Legacy: "<nonce>:<hash> <command> [args]" ---- */
    snprintf(message_copy, sizeof(message_copy), "%s", message);

    char *saveptr_adm;
    char *auth_token = strtok_r(message_copy, " ", &saveptr_adm);
    if (!auth_token)
      return;

    char *saveptr_token;
    char *nonce_str = strtok_r(auth_token, ":", &saveptr_token);
    char *hash_str  = strtok_r(NULL,       "",  &saveptr_token);

    if (!nonce_str || !hash_str)
      return;

    command = strtok_r(NULL, " ", &saveptr_adm);
    if (!command)
      return;
    arg1 = strtok_r(NULL, " ", &saveptr_adm);
    arg2 = strtok_r(NULL, " ", &saveptr_adm);
    arg3 = strtok_r(NULL, " ", &saveptr_adm);

    log_message(L_DEBUG, state,
                "[CMD_DEBUG] legacy Parsed: Cmd='%s' Arg1='%s' Nonce='%s'\n",
                command, (arg1 ? arg1 : "NULL"), nonce_str);

    /* Anti-replay: check nonce before mask lookup */
    nonce_val = strtoull(nonce_str, NULL, 10);
    bool replay = false;
    for (int _ri = 0; _ri < MAX_SEEN_HASHES; _ri++) {
      if (state->admin_nonces[_ri] == nonce_val) { replay = true; break; }
    }

    if (!replay) {
      time_t now_auth = time(NULL);
      user_record_t *candidate = auth_find_user(state, user_host, now_auth);
      if (candidate && auth_verify_password_record(candidate, nonce_str, hash_str)) {
        state->admin_nonces[state->admin_nonce_idx] = nonce_val;
        state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
        if (candidate->type == 'a') { is_admin = true; auth_user = candidate; }
        if (candidate->type == 'o') { is_op   = true; auth_user = candidate; }
        log_message(L_CMD, state,
                    "[CMD] DEPRECATED legacy SHA256-hash auth used by %s — "
                    "upgrade your client to the AES-GCM (~A1) format.\n",
                    user_host);
      }
    }
  }

  if (!is_admin && !is_op) {
    log_message(L_CMD, state, "[CMD_DEBUG] Auth failed for %s.\n", user_host);
    if (used_v1) secure_wipe(v1_plaintext, sizeof(v1_plaintext));
  }

  if (is_admin) {
    log_message(L_CMD, state, "[CMD_ADMIN] Executing Admin Command...\n");

    if (strcasecmp(command, "die") == 0) {
      irc_printf(state, "QUIT :Sayonara.\r\n");
      state->status |= S_DIE;
    } else if (strcasecmp(command, "jump") == 0) {
      if (arg1) {
        /* Jump to named server: match by hostname only, ignore stored port */
        char arg_host[256];
        snprintf(arg_host, sizeof(arg_host), "%s", arg1);
        char *arg_colon = strrchr(arg_host, ':');
        if (arg_colon) *arg_colon = '\0';
        int target_idx = -1;
        for (int i = 0; i < state->server_count; i++) {
          char srv_host[256];
          snprintf(srv_host, sizeof(srv_host), "%s", state->server_list[i]);
          char *srv_colon = strrchr(srv_host, ':');
          if (srv_colon) *srv_colon = '\0';
          if (strcasecmp(arg_host, srv_host) == 0) { target_idx = i; break; }
        }
        if (target_idx == -1) {
          irc_printf(state, "PRIVMSG %s :Error: Server '%s' not in list.\r\n",
                     nick, arg1);
        } else {
          state->current_server_index = target_idx;
          irc_printf(state, "QUIT :Jumping to %s...\r\n", arg1);
          irc_disconnect(state);
        }
      } else {
        irc_printf(state, "QUIT :Jumping servers...\r\n");
        irc_disconnect(state);
      }
    } else if (strcasecmp(command, "join") == 0) {
      char channel_name[MAX_CHAN];
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: join <#channel>\r\n", nick);
        return;
      }
      if (arg1[0] == '#') {
        snprintf(channel_name, sizeof(channel_name), "%s", arg1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }

      chan_t *c = channel_find(state, channel_name);
      if (c && c->is_managed) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Channel %s is already in my list.\r\n",
                   nick, channel_name);
        return;
      }
      if (!c) {
        c = channel_add(state, channel_name);
      }
      if (c) {
        if (arg2)
          snprintf(c->key, MAX_KEY, "%s", arg2);
        c->is_managed = true;      // Mark as managed for syncing
        c->timestamp = time(NULL); // Set timestamp for sync
        log_message(L_DEBUG, state, "[JOIN] Channel %s: re-enabled ts=%ld\n",
                    channel_name, (long)c->timestamp);
      }
      config_write_with_state_pass(state);
      hub_client_push_config(state); // Sync to hub immediately
      irc_printf(state, "PRIVMSG %s :JOIN %s and saving config file.\r\n", nick,
                 arg1);
    } else if (strcasecmp(command, "part") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: part <#channel>\r\n", nick);
        return;
      }
      char channel_name[MAX_CHAN];
      if (arg1[0] == '#') {
        snprintf(channel_name, sizeof(channel_name), "%s", arg1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      chan_t *c = channel_find(state, channel_name);
      if (c) {
        // Soft delete - mark as unmanaged instead of removing
        c->is_managed = false;
        c->timestamp = time(NULL);
        log_message(L_DEBUG, state, "[PART-OP] Channel %s: soft delete ts=%ld\n",
                    channel_name, (long)c->timestamp);
        irc_printf(state, "PART %s\r\n", channel_name);
        config_write_with_state_pass(state);
      }
    } else if (strcasecmp(command, "op") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: op <#channel>\r\n", nick);
        return;
      }
      irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
    } else if (strcasecmp(command, "invite") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: invite <#channel>\r\n", nick);
        return;
      }
      char inv_channel[MAX_CHAN];
      if (arg1[0] == '#' || arg1[0] == '&') {
        snprintf(inv_channel, sizeof(inv_channel), "%s", arg1);
      } else {
        snprintf(inv_channel, sizeof(inv_channel), "#%s", arg1);
      }
      chan_t *ic = channel_find(state, inv_channel);
      if (ic && ic->status == C_IN) {
        bool have_ops = false;
        for (int r = 0; r < ic->roster_count; r++) {
          if (strcasecmp(ic->roster[r].nick, state->current_nick) == 0 &&
              ic->roster[r].is_op) {
            have_ops = true;
            break;
          }
        }
        if (have_ops) {
          irc_printf(state, "INVITE %s %s\r\n", nick, inv_channel);
          irc_printf(state, "PRIVMSG %s :Inviting you to %s\r\n",
                     nick, inv_channel);
          return;
        }
      }
      /* Escalate: hub or encrypted PRIVMSG to trusted bots */
      if (!hub_client_send_invite_request(state, nick, inv_channel)) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char tb_nick[MAX_NICK];
          if (sscanf(state->trusted_bots[i], "%9[^!]", tb_nick) == 1) {
            bot_comms_send_command(state, tb_nick,
                                   "INVITE %s %s", inv_channel, nick);
          }
        }
      }
    } else if (strcasecmp(command, "botpass") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: botpass <password>\r\n", nick);
        return;
      }
      snprintf(state->bot_comm_pass, MAX_PASS, "%s", arg1);
      state->bot_comm_pass_ts = time(NULL);
      config_write_with_state_pass(state);
      irc_printf(state,
                 "PRIVMSG %s :Bot communication password set and saved.\r\n",
                 nick);
    } else if (strcasecmp(command, "+bot") == 0) {
      if (state->hub_count > 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Bot management disabled when hub is configured. "
                   "Bot additions/deletions must be performed on the hub.\r\n",
                   nick);
        return;
      }
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +bot <nick*!*user@hostmask.com>\r\n",
                   nick);
        return;
      }
      for (int i = 0; i < state->trusted_bot_count; i++) {
        if (strcasecmp(state->trusted_bots[i], arg1) == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Error: Trusted bot mask '%s' already exists.\r\n",
              nick, arg1);
          return;
        }
      }
      if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
        char *dup = strdup(arg1);
        if (!dup) return;
        state->trusted_bots[state->trusted_bot_count++] = dup;
        state->trusted_bots[state->trusted_bot_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Added trusted bot: %s\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "-bot") == 0) {
      if (state->hub_count > 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Bot management disabled when hub is configured. "
                   "Bot additions/deletions must be performed on the hub.\r\n",
                   nick);
        return;
      }
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: -bot <nick*!*user@hostmask.com>\r\n",
                   nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->trusted_bot_count; i++) {
        if (strcasecmp(state->trusted_bots[i], arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        free(state->trusted_bots[found_index]);
        for (int i = found_index; i < state->trusted_bot_count - 1; i++) {
          state->trusted_bots[i] = state->trusted_bots[i + 1];
        }
        state->trusted_bot_count--;
        state->trusted_bots[state->trusted_bot_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Removed trusted bot: %s\r\n", nick,
                   arg1);
      }
    } else if (strcasecmp(command, "status") == 0) {
#define ST_SEP  "+----------------------------------------------------------------------------"
#define ST_FOOT "`----------------------------------------------------------------------------"
#define ST_LINE "| "
      /* Uptime */
      char uptime_str[64];
      if (state->connection_time > 0 && (state->status & S_CONNECTED)) {
        long up = (long)(time(NULL) - state->connection_time);
        snprintf(uptime_str, sizeof(uptime_str), "%ldd %ldh %ldm %lds",
                 up/86400, (up%86400)/3600, (up%3600)/60, up%60);
      } else {
        snprintf(uptime_str, sizeof(uptime_str), "N/A");
      }

      /* Network string — include port after hostname */
      char srv_buf[300] = "N/A";
      if (state->actual_server_name[0] != '\0') {
        int srv_port = 0;
        if (state->current_server_index > 0) {
          const char *sl = state->server_list[state->current_server_index - 1];
          const char *colon = sl ? strrchr(sl, ':') : NULL;
          if (colon) srv_port = atoi(colon + 1);
        }
        if (srv_port > 0)
          snprintf(srv_buf, sizeof(srv_buf), "%s:%d", state->actual_server_name, srv_port);
        else
          snprintf(srv_buf, sizeof(srv_buf), "%s", state->actual_server_name);
      } else if (state->current_server_index > 0 &&
                 state->server_list[state->current_server_index - 1]) {
        snprintf(srv_buf, sizeof(srv_buf), "%s",
                 state->server_list[state->current_server_index - 1]);
      }
      const char *srv = srv_buf;
      const char *conn_str = (state->status & S_CONNECTED) ? "CONNECTED" : "DISCONNECTED";

      /* Count active admins and opers */
      int admin_count = 0, oper_count = 0;
      for (int i = 0; i < state->user_record_count; i++) {
        if (!state->user_records[i].is_active) continue;
        if (state->user_records[i].type == 'a') admin_count++;
        else if (state->user_records[i].type == 'o') oper_count++;
      }

      struct timespec st_delay = {0, 80000000}; /* 80ms anti-flood */

      irc_printf(state, "PRIVMSG %s :| ircbot %s status\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_SEP);
      irc_printf(state, "PRIVMSG %s :| Identity : %s (Target: %s) | UUID: %s\r\n",
                 nick, state->current_nick, state->target_nick,
                 state->bot_uuid[0] ? state->bot_uuid : "none");
      irc_printf(state, "PRIVMSG %s :| Uptime   : %s\r\n", nick, uptime_str);
      irc_printf(state, "PRIVMSG %s :| Network  : %s (%s, TLS: %s)\r\n",
                 nick, srv, conn_str, state->is_ssl ? "YES" : "NO");
      nanosleep(&st_delay, NULL);

      /* Servers section — only shown when multiple servers configured */
      if (state->server_count > 1) {
        irc_printf(state, "PRIVMSG %s :+-[ Servers ]---------------------------------------------------------------\r\n", nick);
        char srv_line[600] = ""; int soff = 0;
        for (int i = 0; i < state->server_count; i++) {
          const char *s = state->server_list[i];
          if (!s) continue;
          bool is_cur = (state->current_server_index > 0 &&
                         i == state->current_server_index - 1 &&
                         (state->status & S_CONNECTED));
          char entry[140];
          snprintf(entry, sizeof(entry), "%s%s", is_cur ? "*" : " ", s);
          int elen = (int)strlen(entry);
          if (soff > 0 && soff + 2 + elen < (int)sizeof(srv_line) - 1) {
            srv_line[soff++] = ','; srv_line[soff++] = ' ';
          }
          if (soff + elen < (int)sizeof(srv_line) - 1) {
            memcpy(srv_line + soff, entry, elen);
            soff += elen; srv_line[soff] = '\0';
          }
        }
        irc_printf(state, "PRIVMSG %s :| %s\r\n", nick, srv_line);
        nanosleep(&st_delay, NULL);
      }

      /* Channels section — collect IN and OUT into comma-wrapped lines */
      irc_printf(state, "PRIVMSG %s :+-[ Channels ]---------------------------------------------------------------\r\n", nick);
      {
        /* Build IN channel list */
        char in_buf[800] = "", out_buf[400] = "";
        int in_off = 0, out_off = 0;
        for (chan_t *c = state->chanlist; c; c = c->next) {
          if (!c->is_managed) continue;
          char entry[128];
          if (c->status == C_IN) {
            snprintf(entry, sizeof(entry), "%s%s",
                     c->i_am_opped ? "@" : "", c->name);
            int elen = (int)strlen(entry);
            if (in_off > 0 && in_off + 2 + elen < (int)sizeof(in_buf) - 1) {
              in_buf[in_off++] = ','; in_buf[in_off++] = ' ';
            }
            if (in_off + elen < (int)sizeof(in_buf) - 1) {
              memcpy(in_buf + in_off, entry, elen);
              in_off += elen; in_buf[in_off] = '\0';
            }
          } else {
            int elen = (int)strlen(c->name);
            if (out_off > 0 && out_off + 2 + elen < (int)sizeof(out_buf) - 1) {
              out_buf[out_off++] = ','; out_buf[out_off++] = ' ';
            }
            if (out_off + elen < (int)sizeof(out_buf) - 1) {
              memcpy(out_buf + out_off, c->name, elen);
              out_off += elen; out_buf[out_off] = '\0';
            }
          }
        }
        /* Word-wrap and send IN line(s): prefix "| (IN)  " = 8 chars, content 68 */
        if (in_buf[0]) {
          const char *pfx1 = "| (IN)  ", *pfx2 = "|        ";
          int cw = 68;
          char *p = in_buf; int first = 1;
          while (*p) {
            char seg[80]; int n = 0;
            while (*p && n < cw) seg[n++] = *p++;
            /* back up to last comma+space if not at end */
            if (*p) {
              int back = n;
              while (back > 0 && !(seg[back-1] == ' ' && back > 1 && seg[back-2] == ','))
                back--;
              if (back > 0) { p -= (n - back); n = back; }
            }
            seg[n] = '\0';
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? pfx1 : pfx2, seg);
            first = 0;
          }
        } else {
          irc_printf(state, "PRIVMSG %s :| (IN)  (none)\r\n", nick);
        }
        if (out_buf[0])
          irc_printf(state, "PRIVMSG %s :| (OUT) %s\r\n", nick, out_buf);
      }
      nanosleep(&st_delay, NULL);

      /* Access Control — counts only */
      irc_printf(state, "PRIVMSG %s :+-[ Access Control ]---------------------------------------------------------\r\n", nick);
      irc_printf(state, "PRIVMSG %s :| Admins : %-4d  Ops: %d\r\n",
                 nick, admin_count, oper_count);
      nanosleep(&st_delay, NULL);

      /* Hub Config or standalone Bots section */
#define HUB_TRUST_MAX 100
#define BOTS_PFX1 "| Bots   : "
#define BOTS_PFX2 "|          "
#define BOTS_CW   66
      if (state->hub_count > 0) {
        /* Hub is configured — show full Hub Config */
        irc_printf(state, "PRIVMSG %s :+-[ Hub Config ]-------------------------------------------------------------\r\n", nick);
        if (state->hub_connected && state->current_hub[0]) {
          if (state->hub_connect_time > 0 && state->hub_authenticated) {
            long hup = (long)(time(NULL) - state->hub_connect_time);
            char hub_up_str[64];
            snprintf(hub_up_str, sizeof(hub_up_str), "%ldd %ldh %ldm %lds",
                     hup/86400, (hup%86400)/3600, (hup%3600)/60, hup%60);
            irc_printf(state, "PRIVMSG %s :| Hub    : %s (CONNECTED, UPTIME: %s)\r\n",
                       nick, state->current_hub, hub_up_str);
          } else {
            irc_printf(state, "PRIVMSG %s :| Hub    : %s (CONNECTED)\r\n",
                       nick, state->current_hub);
          }
        } else {
          irc_printf(state, "PRIVMSG %s :| Hub    : DISCONNECTED\r\n", nick);
        }
        /* Configured hubs */
        {
          char hubs_line[300] = ""; int hoff = 0;
          for (int i = 0; i < state->hub_count; i++) {
            int hlen = (int)strlen(state->hub_list[i]);
            if (hoff) { hubs_line[hoff++] = ','; hubs_line[hoff++] = ' '; }
            if (hoff + hlen < (int)sizeof(hubs_line) - 1) {
              memcpy(hubs_line + hoff, state->hub_list[i], hlen);
              hoff += hlen; hubs_line[hoff] = '\0';
            }
          }
          irc_printf(state, "PRIVMSG %s :| Hubs   : %s\r\n", nick, hubs_line);
        }
        /* Bots — word-wrap, truncate after 100 */
        if (state->trusted_bot_count > 0) {
          char trust_line[512] = ""; int toff = 0;
          int first = 1, shown = 0;
          for (int i = 0; i < state->trusted_bot_count && shown < HUB_TRUST_MAX; i++, shown++) {
            char tname[64] = "";
            sscanf(state->trusted_bots[i], "%63[^!]", tname);
            int tlen = (int)strlen(tname);
            int need = toff ? tlen + 2 : tlen;
            if (toff && toff + need > BOTS_CW) {
              irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
              first = 0; toff = 0; trust_line[0] = '\0';
            }
            if (toff) { trust_line[toff++] = ','; trust_line[toff++] = ' '; }
            memcpy(trust_line + toff, tname, tlen);
            toff += tlen; trust_line[toff] = '\0';
          }
          if (toff)
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
          if (state->trusted_bot_count > HUB_TRUST_MAX)
            irc_printf(state, "PRIVMSG %s :|          ...and %d more\r\n", nick,
                       state->trusted_bot_count - HUB_TRUST_MAX);
        } else {
          irc_printf(state, "PRIVMSG %s :| Bots   : (none)\r\n", nick);
        }
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      } else if (state->trusted_bot_count > 0) {
        /* No hub — standalone bot-to-bot mode, show Bots section only */
        irc_printf(state, "PRIVMSG %s :+-[ Bots ]-------------------------------------------------------------------\r\n", nick);
        char trust_line[512] = ""; int toff = 0;
        int first = 1, shown = 0;
        for (int i = 0; i < state->trusted_bot_count && shown < HUB_TRUST_MAX; i++, shown++) {
          char tname[64] = "";
          sscanf(state->trusted_bots[i], "%63[^!]", tname);
          int tlen = (int)strlen(tname);
          int need = toff ? tlen + 2 : tlen;
          if (toff && toff + need > BOTS_CW) {
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
            first = 0; toff = 0; trust_line[0] = '\0';
          }
          if (toff) { trust_line[toff++] = ','; trust_line[toff++] = ' '; }
          memcpy(trust_line + toff, tname, tlen);
          toff += tlen; trust_line[toff] = '\0';
        }
        if (toff)
          irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
        if (state->trusted_bot_count > HUB_TRUST_MAX)
          irc_printf(state, "PRIVMSG %s :|          ...and %d more\r\n", nick,
                     state->trusted_bot_count - HUB_TRUST_MAX);
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      } else {
        /* No hub, no bots — just close the box */
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      }
#undef HUB_TRUST_MAX
#undef BOTS_PFX1
#undef BOTS_PFX2
#undef BOTS_CW
#undef ST_SEP
#undef ST_FOOT
#undef ST_LINE
    } else if (strcasecmp(command, "givenick") == 0) {
      irc_printf(state,
                 "PRIVMSG %s :You have about %d seconds to retrieve.\r\n", nick,
                 NICK_TAKE_TIME);
      irc_generate_new_nick(state);
      state->nick_release_time = time(NULL);
    } else if (strcasecmp(command, "chnick") == 0) {
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chnick <oldnick> <newnick>\r\n", nick);
        return;
      }
      if (!is_valid_bot_nick(arg2)) {
        if (strchr(arg2, '|'))
          irc_printf(state,
              "PRIVMSG %s :Error: New nick cannot contain '|'.\r\n", nick);
        else
          irc_printf(state,
              "PRIVMSG %s :Error: New nick too long (max %d chars).\r\n",
              nick, MAX_NICK - 1);
        return;
      }
      /* Uniqueness check: newnick must not already exist in any type */
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg2) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use.\r\n",
                     nick, arg2);
          return;
        }
      }
      if (strcasecmp(state->target_nick, arg2) == 0) {
        irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use by this bot.\r\n",
                   nick, arg2);
        return;
      }
      for (int i = 0; i < state->trusted_bot_count; i++) {
        char bnick[MAX_NICK] = "";
        sscanf(state->trusted_bots[i], "%9[^!]", bnick);
        if (strcasecmp(bnick, arg2) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use by a bot.\r\n",
                     nick, arg2);
          return;
        }
      }
      bool cn_found = false;
      /* Case 1: this bot's own target nick */
      if (strcasecmp(state->target_nick, arg1) == 0) {
        snprintf(state->target_nick, MAX_NICK, "%s", arg2);
        state->current_nick_ts = time(NULL);
        config_write_with_state_pass(state);
        hub_client_push_delta(state, "n", arg2, state->current_nick_ts);
        irc_printf(state, "PRIVMSG %s :This bot's nick changed to '%s' and saved.\r\n",
                   nick, arg2);
        cn_found = true;
      }
      /* Case 2: admin or oper */
      if (!cn_found) {
        for (int i = 0; i < state->user_record_count; i++) {
          user_record_t *u = &state->user_records[i];
          if (u->is_active && strcasecmp(u->name, arg1) == 0) {
            snprintf(u->name, sizeof(u->name), "%s", arg2);
            u->timestamp = time(NULL);
            config_write_with_state_pass(state);
            hub_client_push_admin_delta(state);
            irc_printf(state, "PRIVMSG %s :User '%s' renamed to '%s'.\r\n",
                       nick, arg1, arg2);
            cn_found = true;
            break;
          }
        }
      }
      /* Case 3: trusted bot */
      if (!cn_found) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char bnick[MAX_NICK] = "", bmask[MAX_MASK_LEN] = "";
          char buuid[64] = "";
          long bts = 0;
          sscanf(state->trusted_bots[i], "%9[^!]", bnick);
          if (strcasecmp(bnick, arg1) != 0) continue;
          sscanf(state->trusted_bots[i], "%255[^|]|%63[^|]|%ld",
                 bmask, buuid, &bts);
          /* Replace the nick part of the mask (up to '!') */
          char newmask[MAX_MASK_LEN] = "";
          char *bang = strchr(bmask, '!');
          if (bang)
            snprintf(newmask, sizeof(newmask), "%s%s", arg2, bang);
          else
            snprintf(newmask, sizeof(newmask), "%s", arg2);
          long new_ts = time(NULL);
          char new_entry[512];
          snprintf(new_entry, sizeof(new_entry), "%s|%s|%ld",
                   newmask, buuid, new_ts);
          char *dup_entry = strdup(new_entry);
          if (!dup_entry) {
            irc_printf(state, "PRIVMSG %s :Error: Memory allocation failed.\r\n", nick);
            return;
          }
          free(state->trusted_bots[i]);
          state->trusted_bots[i] = dup_entry;
          config_write_with_state_pass(state);
          /* Send SETNICK to the bot via encrypted bot comms (old nick) */
          bot_comms_send_command(state, arg1, "SETNICK %s", arg2);
          irc_printf(state, "PRIVMSG %s :Bot '%s' renamed to '%s' and notified.\r\n",
                     nick, arg1, arg2);
          cn_found = true;
          break;
        }
      }
      if (!cn_found)
        irc_printf(state, "PRIVMSG %s :Error: No bot/admin/oper named '%s' found.\r\n",
                   nick, arg1);
    } else if (strcasecmp(command, "saveconf") == 0) {
      config_write_with_state_pass(state);
      irc_printf(state, "PRIVMSG %s :Configuration state saved to %s.\r\n",
                 nick, CONFIG_FILE);
    } else if (strcasecmp(command, "setlog") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: setlog <loglevel> :: LOGLEVELS: "
                   "0=NONE,15=INFO,63=DEBUG\r\n",
                   nick);
        return;
      }
      bool is_valid_int = true;
      for (int i = 0; arg1[i] != '\0'; i++)
        if (!isdigit(arg1[i])) {
          is_valid_int = false;
          break;
        }
      if (is_valid_int) {
        int new_level = atoi(arg1);
        state->log_type = (log_type_t)new_level;
        irc_printf(state, "PRIVMSG %s :Log level set to %d.\r\n", nick,
                   new_level);
        config_write_with_state_pass(state);
      } else
        irc_printf(state,
                   "PRIVMSG %s :Invalid log level. Please provide a valid "
                   "integer.\r\n",
                   nick);
    } else if (strcasecmp(command, "getlog") == 0) {
      if (!arg1) {
        irc_printf(
            state,
            "PRIVMSG %s :Syntax: getlog <level> [lines]. Levels are 'msg' "
            "'ctcp' 'info' 'cmd' 'raw' 'debug'. Default: %d. Max: %d.\r\n",
            nick, DEFAULT_LOG_LINES, MAX_LOG_LINES);
        return;
      }
      int buffer_index = -1;
      if (strcasecmp(arg1, "msg") == 0)
        buffer_index = 0;
      else if (strcasecmp(arg1, "ctcp") == 0)
        buffer_index = 1;
      else if (strcasecmp(arg1, "info") == 0)
        buffer_index = 2;
      else if (strcasecmp(arg1, "cmd") == 0)
        buffer_index = 3;
      else if (strcasecmp(arg1, "raw") == 0)
        buffer_index = 4;
      else if (strcasecmp(arg1, "debug") == 0)
        buffer_index = 5;

      if (buffer_index == -1) {
        irc_printf(state, "PRIVMSG %s :Error: Unknown log level '%s'.\r\n",
                   nick, arg1);
        return;
      }

      int lines_to_show = DEFAULT_LOG_LINES;
      if (arg2) {
        lines_to_show = atoi(arg2);
        if (lines_to_show <= 0)
          lines_to_show = DEFAULT_LOG_LINES;
        if (lines_to_show > MAX_LOG_LINES) {
          irc_printf(state, "PRIVMSG %s :Warning: Line count capped at %d.\r\n",
                     nick, MAX_LOG_LINES);
          lines_to_show = MAX_LOG_LINES;
        }
      }

      log_entry_t *matches[LOG_BUFFER_LINES];
      int matches_found = 0;
      log_buffer_t *log_buf_ptr = &state->in_memory_logs[buffer_index];

      for (int i = 0; i < LOG_BUFFER_LINES; i++) {
        int idx = (log_buf_ptr->log_idx + i) % LOG_BUFFER_LINES;
        log_entry_t *entry = &log_buf_ptr->entries[idx];
        if (entry->line[0] != '\0')
          matches[matches_found++] = entry;
      }

      int lines_to_print =
          (matches_found < lines_to_show) ? matches_found : lines_to_show;
      int start_index = matches_found - lines_to_print;
      irc_printf(state,
                 "PRIVMSG %s :--- Start of Log (%s) - Showing last %d of %d "
                 "lines --- \r\n",
                 nick, arg1, lines_to_print, matches_found);

      struct timespec delay = {0, 250000000};
      for (int i = matches_found - 1; i >= start_index; i--) {
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, matches[i]->line);
        nanosleep(&delay, NULL);
      }
      irc_printf(state, "PRIVMSG %s :--- End of Log (%s) --- \r\n", nick, arg1);
    } else if (strcasecmp(command, "admins") == 0) {
      struct timespec delay = {0, 100000000};
      /* Find max name width for alignment (min 8) */
      int name_w = 8;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].type != 'a') continue;
        int nl = (int)strlen(state->user_records[i].name);
        if (nl > name_w) name_w = nl;
      }
      irc_printf(state, "PRIVMSG %s :| ircbot %s admins\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      int shown = 0;
      for (int i = 0; i < state->user_record_count && shown < BOT_STATUS_MAX_LINES; i++) {
        user_record_t *u = &state->user_records[i];
        if (u->type != 'a') continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm = gmtime(&u->last_seen);
          strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm);
        }
        char del_tag[16] = "";
        if (!u->is_active) snprintf(del_tag, sizeof(del_tag), " [deleted]");
        irc_printf(state, "PRIVMSG %s :| %-*s  (last seen: %s)%s\r\n",
                   nick, name_w, u->name, ts_buf, del_tag);
        shown++;
        nanosleep(&delay, NULL);
      }
      if (shown == 0)
        irc_printf(state, "PRIVMSG %s :| (no admins)\r\n", nick);
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "opers") == 0) {
      struct timespec delay = {0, 100000000};
      int name_w = 8;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].type != 'o') continue;
        int nl = (int)strlen(state->user_records[i].name);
        if (nl > name_w) name_w = nl;
      }
      irc_printf(state, "PRIVMSG %s :| ircbot %s opers\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      int shown = 0;
      for (int i = 0; i < state->user_record_count && shown < BOT_STATUS_MAX_LINES; i++) {
        user_record_t *u = &state->user_records[i];
        if (u->type != 'o') continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm = gmtime(&u->last_seen);
          strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm);
        }
        char del_tag[16] = "";
        if (!u->is_active) snprintf(del_tag, sizeof(del_tag), " [deleted]");
        irc_printf(state, "PRIVMSG %s :| %-*s  (last seen: %s)%s\r\n",
                   nick, name_w, u->name, ts_buf, del_tag);
        shown++;
        nanosleep(&delay, NULL);
      }
      if (shown == 0)
        irc_printf(state, "PRIVMSG %s :| (no opers)\r\n", nick);
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "match") == 0) {
      /* Show active records for named user or * for all */
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: match <name|*>\r\n", nick);
        return;
      }
      bool match_all = (strcmp(arg1, "*") == 0);
      irc_printf(state, "PRIVMSG %s :| ircbot %s match%s\r\n", nick, BOT_VERSION,
                 match_all ? " *" : "");
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      struct timespec delay = {0, 100000000};
      int shown = 0;
      for (int i = 0; i < state->user_record_count; i++) {
        user_record_t *u = &state->user_records[i];
        if (!match_all && strcasecmp(u->name, arg1) != 0) continue;
        if (!u->is_active) continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm_utc = gmtime(&u->last_seen);
          strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm_utc);
        }
        irc_printf(state, "PRIVMSG %s :| [%c] %-20s  (last seen: %s)\r\n",
                   nick, u->type, u->name, ts_buf);
        nanosleep(&delay, NULL);
        for (int j = 0; j < state->mask_record_count; j++) {
          mask_record_t *m = &state->mask_records[j];
          if (strcmp(m->uuid, u->uuid) != 0) continue;
          if (!m->is_active) continue;
          char used_buf[48];
          if (m->last_used == 0) {
            snprintf(used_buf, sizeof(used_buf), "never");
          } else {
            struct tm *tm_used = gmtime(&m->last_used);
            strftime(used_buf, sizeof(used_buf), "%Y-%m-%d %H:%M:%S UTC", tm_used);
          }
          irc_printf(state, "PRIVMSG %s :|   %s  (last used: %s)\r\n",
                     nick, m->mask, used_buf);
          nanosleep(&delay, NULL);
          if (++shown >= BOT_STATUS_MAX_LINES) goto match_done;
        }
      }
      /* If no user record found and not wildcard, check trusted bots */
      if (shown == 0 && !match_all) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char bot_mask[256] = "", bot_uuid[64] = "";
          long bot_ts = 0;
          sscanf(state->trusted_bots[i], "%255[^|]|%63[^|]|%ld",
                 bot_mask, bot_uuid, &bot_ts);
          char bot_nick[MAX_NICK] = "";
          sscanf(bot_mask, "%9[^!]", bot_nick);
          if (strcasecmp(bot_nick, arg1) != 0) continue;
          /* Found a matching bot */
          char ts_buf[48];
          if (bot_ts == 0) {
            snprintf(ts_buf, sizeof(ts_buf), "never");
          } else {
            time_t bts = (time_t)bot_ts;
            struct tm *tm_utc = gmtime(&bts);
            strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm_utc);
          }
          irc_printf(state, "PRIVMSG %s :| [b] %-20s  (last seen: %s)\r\n",
                     nick, bot_nick, ts_buf);
          nanosleep(&delay, NULL);
          if (bot_mask[0])
            irc_printf(state, "PRIVMSG %s :|   mask: %s\r\n", nick, bot_mask);
          if (bot_uuid[0])
            irc_printf(state, "PRIVMSG %s :|   uuid: %s\r\n", nick, bot_uuid);
          const char *hub_str = (state->hub_connected && state->current_hub[0])
                                ? state->current_hub : "none";
          irc_printf(state, "PRIVMSG %s :|   hub : %s\r\n", nick, hub_str);
          shown++;
          nanosleep(&delay, NULL);
          break;
        }
      }
      if (shown == 0 && !match_all)
        irc_printf(state, "PRIVMSG %s :| unknown user: %s\r\n", nick, arg1);
      match_done:
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "+admin") == 0) {
      /* +admin <name> <password> <usermask> */
      if (!arg1 || !arg2 || !arg3) {
        irc_printf(state, "PRIVMSG %s :Syntax: +admin <name> <password> <nick!user@host>\r\n", nick);
        return;
      }
      if (!strchr(arg3,'!') || !strchr(arg3,'@')) {
        irc_printf(state, "PRIVMSG %s :Error: mask must contain ! and @\r\n", nick);
        return;
      }
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: name '%s' already exists.\r\n", nick, arg1);
          return;
        }
      }
      if (state->user_record_count >= MAX_USER_RECORDS) {
        irc_printf(state, "PRIVMSG %s :Error: user record table full.\r\n", nick); return;
      }
      if (state->mask_record_count >= MAX_USER_MASKS) {
        irc_printf(state, "PRIVMSG %s :Error: mask table full.\r\n", nick); return;
      }
      /* Generate UUID using random bytes */
      unsigned char rnd[16]; RAND_bytes(rnd, sizeof(rnd));
      rnd[6]=(rnd[6]&0x0f)|0x40; rnd[8]=(rnd[8]&0x3f)|0x80;
      char new_uuid[37];
      snprintf(new_uuid, sizeof(new_uuid),
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
               rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);
      time_t now = time(NULL);
      user_record_t *u = &state->user_records[state->user_record_count++];
      memset(u, 0, sizeof(*u));
      snprintf(u->uuid, sizeof(u->uuid), "%s", new_uuid);
      snprintf(u->name, sizeof(u->name), "%s", arg1);
      snprintf(u->password, sizeof(u->password), "%s", arg2);
      u->type = 'a'; u->is_active = true; u->timestamp = now;
      mask_record_t *m = &state->mask_records[state->mask_record_count++];
      memset(m, 0, sizeof(*m));
      snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
      snprintf(m->mask, sizeof(m->mask), "%s", arg3);
      m->is_active = true; m->timestamp = now;
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Admin '%s' added with mask %s\r\n", nick, arg1, arg3);

    } else if (strcasecmp(command, "-admin") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -admin <name>\r\n", nick); return;
      }
      user_record_t *target = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active && state->user_records[i].type=='a' &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          target = &state->user_records[i]; break;
        }
      }
      if (!target) { irc_printf(state, "PRIVMSG %s :Error: admin '%s' not found.\r\n", nick, arg1); return; }
      target->is_active = false;
      target->timestamp = time(NULL);
      for (int i = 0; i < state->mask_record_count; i++)
        if (strcmp(state->mask_records[i].uuid, target->uuid) == 0) {
          state->mask_records[i].is_active = false;
          state->mask_records[i].timestamp = time(NULL);
        }
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Admin '%s' and all their masks removed.\r\n", nick, arg1);

    } else if (strcasecmp(command, "+oper") == 0) {
      /* +oper <name> <password> <usermask> */
      if (!arg1 || !arg2 || !arg3) {
        irc_printf(state, "PRIVMSG %s :Syntax: +oper <name> <password> <nick!user@host>\r\n", nick);
        return;
      }
      if (!strchr(arg3,'!') || !strchr(arg3,'@')) {
        irc_printf(state, "PRIVMSG %s :Error: mask must contain ! and @\r\n", nick); return;
      }
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: name '%s' already exists.\r\n", nick, arg1); return;
        }
      }
      if (state->user_record_count >= MAX_USER_RECORDS || state->mask_record_count >= MAX_USER_MASKS) {
        irc_printf(state, "PRIVMSG %s :Error: table full.\r\n", nick); return;
      }
      unsigned char rnd2[16]; RAND_bytes(rnd2, sizeof(rnd2));
      rnd2[6]=(rnd2[6]&0x0f)|0x40; rnd2[8]=(rnd2[8]&0x3f)|0x80;
      char new_uuid2[37];
      snprintf(new_uuid2, sizeof(new_uuid2),
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               rnd2[0],rnd2[1],rnd2[2],rnd2[3],rnd2[4],rnd2[5],rnd2[6],rnd2[7],
               rnd2[8],rnd2[9],rnd2[10],rnd2[11],rnd2[12],rnd2[13],rnd2[14],rnd2[15]);
      time_t now2 = time(NULL);
      user_record_t *u2 = &state->user_records[state->user_record_count++];
      memset(u2, 0, sizeof(*u2));
      snprintf(u2->uuid, sizeof(u2->uuid), "%s", new_uuid2);
      snprintf(u2->name, sizeof(u2->name), "%s", arg1);
      snprintf(u2->password, sizeof(u2->password), "%s", arg2);
      u2->type = 'o'; u2->is_active = true; u2->timestamp = now2;
      mask_record_t *m2 = &state->mask_records[state->mask_record_count++];
      memset(m2, 0, sizeof(*m2));
      snprintf(m2->uuid, sizeof(m2->uuid), "%s", new_uuid2);
      snprintf(m2->mask, sizeof(m2->mask), "%s", arg3);
      m2->is_active = true; m2->timestamp = now2;
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Oper '%s' added with mask %s\r\n", nick, arg1, arg3);

    } else if (strcasecmp(command, "-oper") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -oper <name>\r\n", nick); return;
      }
      user_record_t *target_o = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active && state->user_records[i].type=='o' &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          target_o = &state->user_records[i]; break;
        }
      }
      if (!target_o) { irc_printf(state, "PRIVMSG %s :Error: oper '%s' not found.\r\n", nick, arg1); return; }
      target_o->is_active = false;
      target_o->timestamp = time(NULL);
      for (int i = 0; i < state->mask_record_count; i++)
        if (strcmp(state->mask_records[i].uuid, target_o->uuid) == 0) {
          state->mask_records[i].is_active = false;
          state->mask_records[i].timestamp = time(NULL);
        }
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Oper '%s' and all their masks removed.\r\n", nick, arg1);

    } else if (strcasecmp(command, "+usermask") == 0) {
      /* +usermask <name> <mask> */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: +usermask <name> <nick!user@host>\r\n", nick); return;
      }
      if (!strchr(arg2,'!') || !strchr(arg2,'@')) {
        irc_printf(state, "PRIVMSG %s :Error: mask must contain ! and @\r\n", nick); return;
      }
      user_record_t *tum = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          tum = &state->user_records[i]; break;
        }
      }
      if (!tum) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      for (int i = 0; i < state->mask_record_count; i++) {
        if (state->mask_records[i].is_active &&
            strcmp(state->mask_records[i].uuid, tum->uuid) == 0 &&
            strcasecmp(state->mask_records[i].mask, arg2) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: mask already exists.\r\n", nick); return;
        }
      }
      if (state->mask_record_count >= MAX_USER_MASKS) {
        irc_printf(state, "PRIVMSG %s :Error: mask table full.\r\n", nick); return;
      }
      char tum_uuid[37]; snprintf(tum_uuid, sizeof(tum_uuid), "%s", tum->uuid);
      mask_record_t *nm = &state->mask_records[state->mask_record_count++];
      memset(nm, 0, sizeof(*nm));
      snprintf(nm->uuid, sizeof(nm->uuid), "%s", tum_uuid);
      snprintf(nm->mask, sizeof(nm->mask), "%s", arg2);
      nm->is_active = true; nm->timestamp = time(NULL);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Mask %s added to %s\r\n", nick, arg2, arg1);

    } else if (strcasecmp(command, "-usermask") == 0) {
      /* -usermask <name> <mask> */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: -usermask <name> <mask>\r\n", nick); return;
      }
      user_record_t *dum = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          dum = &state->user_records[i]; break;
        }
      }
      if (!dum) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      mask_record_t *fdm = NULL;
      for (int i = 0; i < state->mask_record_count; i++) {
        if (state->mask_records[i].is_active &&
            strcmp(state->mask_records[i].uuid, dum->uuid) == 0 &&
            strcasecmp(state->mask_records[i].mask, arg2) == 0) {
          fdm = &state->mask_records[i]; break;
        }
      }
      if (!fdm) { irc_printf(state, "PRIVMSG %s :Error: mask '%s' not found for %s.\r\n", nick, arg2, arg1); return; }
      fdm->is_active = false;
      fdm->timestamp = time(NULL);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Mask %s removed from %s\r\n", nick, arg2, arg1);

    } else if (strcasecmp(command, "+server") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +server <irc.server.net:6667>\r\n",
                   nick);
        return;
      }
      if (state->server_count < MAX_SERVERS) {
        char *dup = strdup(arg1);
        if (!dup) return;
        state->server_list[state->server_count++] = dup;
        state->server_list[state->server_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Added server '%s' and saved config.\r\n",
                   nick, arg1);
      } else
        irc_printf(state, "PRIVMSG %s :Error: Server list is full.\r\n", nick);
    } else if (strcasecmp(command, "-server") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -server <server>\r\n", nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->server_count; i++)
        if (strcasecmp(state->server_list[i], arg1) == 0) {
          found_index = i;
          break;
        }
      if (found_index != -1) {
        free(state->server_list[found_index]);
        for (int i = found_index; i < state->server_count - 1; i++)
          state->server_list[i] = state->server_list[i + 1];
        state->server_count--;
        state->server_list[state->server_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state,
                   "PRIVMSG %s :Removed server '%s' and saved config.\r\n",
                   nick, arg1);
      }
    } else if (strcasecmp(command, "update") == 0) {
      if (arg1)
        updater_perform_upgrade(state, nick, arg1);
      else
        updater_check_for_updates(state, nick);
    } else if (strcasecmp(command, "+hub") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: +hub <ip:port>\r\n", nick);
        return;
      }
      // Check for duplicates
      for (int i = 0; i < state->hub_count; i++) {
        if (strcmp(state->hub_list[i], arg1) == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Error: Hub '%s' already exists.\r\n",
                     nick, arg1);
          return;
        }
      }
      if (state->hub_count < MAX_SERVERS) {
        char *dup = strdup(arg1);
        if (!dup) return;
        state->hub_list[state->hub_count++] = dup;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Added Hub: %s\r\n", nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Hub list is full.\r\n", nick);
      }
    } else if (strcasecmp(command, "-hub") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -hub <ip:port>\r\n", nick);
        return;
      }
      int found = -1;
      for (int i = 0; i < state->hub_count; i++)
        if (strcmp(state->hub_list[i], arg1) == 0) {
          found = i;
          break;
        }
      if (found != -1) {
        // Check if this is the currently connected hub
        bool is_current_hub = (state->hub_connected &&
                               strcmp(state->current_hub, arg1) == 0);

        // If removing the currently connected hub, disconnect first
        if (is_current_hub) {
          irc_printf(state, "PRIVMSG %s :Disconnecting from current hub: %s\r\n",
                     nick, arg1);
          hub_client_disconnect(state);
        }

        // Remove the hub from the list
        free(state->hub_list[found]);
        for (int i = found; i < state->hub_count - 1; i++)
          state->hub_list[i] = state->hub_list[i + 1];
        state->hub_count--;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Removed Hub: %s\r\n", nick, arg1);

        // If we disconnected and there are other hubs available, reconnect
        if (is_current_hub && state->hub_count > 0) {
          irc_printf(state, "PRIVMSG %s :Reconnecting to another hub...\r\n", nick);
          state->last_hub_connect_attempt = 0; // Reset cooldown
          hub_client_connect(state);
        } else if (is_current_hub && state->hub_count == 0) {
          irc_printf(state, "PRIVMSG %s :No other hubs available to connect to.\r\n",
                     nick);
        }
      }
    } else if (strcasecmp(command, "sethubkey") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: sethubkey <88-char-base64-Curve25519-key>\r\n",
                   nick);
      } else {
        // Reject legacy multipart syntax
        if (strchr(arg1, '/') && strchr(arg1, ':')) {
          irc_printf(state,
                     "PRIVMSG %s :ERROR: Multipart keys no longer needed. "
                     "Curve25519 keys fit in one IRC message (88 chars).\r\n",
                     nick);
        } else {
          // Validate: decode base64 → must be exactly 64 bytes
          int dec_len = 0;
          unsigned char *dec = base64_decode(arg1, &dec_len);

          if (!dec || dec_len != HUB_KEY_RAW_LEN) {
            irc_printf(state,
                       "PRIVMSG %s :ERROR: Invalid key. Need 88-char base64 "
                       "that decodes to exactly 64 bytes (Curve25519).\r\n",
                       nick);
            if (dec) free(dec);
          } else {
            // Validate Ed25519 and X25519 halves can be loaded
            EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, dec, 32);
            EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, dec + 32, 32);
            memset(dec, 0, 64);
            free(dec);

            if (!ep || !xp) {
              irc_printf(state,
                         "PRIVMSG %s :ERROR: Invalid Curve25519 key material.\r\n",
                         nick);
              if (ep) EVP_PKEY_free(ep);
              if (xp) EVP_PKEY_free(xp);
            } else {
              EVP_PKEY_free(ep);
              EVP_PKEY_free(xp);

              snprintf(state->hub_key, sizeof(state->hub_key), "%s", arg1);
              config_write_with_state_pass(state);
              irc_printf(state,
                         "PRIVMSG %s :✓ Curve25519 key set. Reconnecting...\r\n",
                         nick);

              if (state->hub_fd != -1) {
                close(state->hub_fd);
                state->hub_fd = -1;
              }
              state->last_hub_connect_attempt = 0;
              hub_client_connect(state);
            }
          }
        }
      }
    }

    else if (strcasecmp(command, "sethubpub") == 0) {
      /* Set the hub's long-term Ed25519 PUBLIC key used by the bot to verify
       * the hub's signature in the v2 handshake. Accepts either:
       *   - 44-char base64 = raw 32-byte Ed25519 pubkey
       *   - 88-char base64 = combined 64-byte Ed25519+X25519 pubkey
       *     (we take the first 32 bytes — same format as hub_public.b64) */
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: sethubpub <44-char or 88-char base64 hub pubkey>\r\n",
                   nick);
      } else {
        int dec_len = 0;
        unsigned char *dec = base64_decode(arg1, &dec_len);
        if (!dec || (dec_len != 32 && dec_len != HUB_KEY_RAW_LEN)) {
          irc_printf(state,
                     "PRIVMSG %s :ERROR: Need base64 of 32-byte Ed25519 pubkey "
                     "or 64-byte combined Curve25519 pubkey.\r\n", nick);
          if (dec) free(dec);
        } else {
          memcpy(state->hub_remote_ed_pub, dec, 32);
          state->hub_remote_ed_pub_set = true;
          memset(dec, 0, dec_len);
          free(dec);
          config_write_with_state_pass(state);
          irc_printf(state,
                     "PRIVMSG %s :✓ Hub Ed25519 pubkey saved. Next handshake "
                     "will REQUIRE a valid hub signature.\r\n", nick);
        }
      }
    }

    else if (strcasecmp(command, "setuuid") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: setuuid <uuid>\r\n", nick);
        return;
      }

      // Sanitize UUID - remove spaces, convert to lowercase
      char sanitized[64] = {0};
      int out_idx = 0;
      for (int i = 0; arg1[i] && out_idx < 63; i++) {
        char c = arg1[i];
        // Allow hex chars (0-9, a-f, A-F) and dashes
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F') || c == '-') {
          sanitized[out_idx++] = tolower(c);
        }
      }
      sanitized[out_idx] = '\0';

      // Validate UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
      if (strlen(sanitized) != 36 || sanitized[8] != '-' ||
          sanitized[13] != '-' || sanitized[18] != '-' ||
          sanitized[23] != '-') {
        irc_printf(state,
                   "PRIVMSG %s :Invalid UUID format. Expected: "
                   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\r\n",
                   nick);
        return;
      }

      // Store UUID
      snprintf(state->bot_uuid, sizeof(state->bot_uuid), "%s", sanitized);
      config_write_with_state_pass(state);
      irc_printf(state,
                 "PRIVMSG %s :UUID set to: %s. Reconnecting to hub...\r\n",
                 nick, state->bot_uuid);

      // Force Hub Reconnect
      if (state->hub_fd != -1) {
        close(state->hub_fd);
        state->hub_fd = -1;
      }
      state->last_hub_connect_attempt = 0;
      hub_client_connect(state);
    } else if (strcasecmp(command, "chpass") == 0) {
      /* chpass <name> <newpassword> — admin changes anyone; oper changes own only */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chpass <name> <newpassword>\r\n", nick); return;
      }
      user_record_t *cp_target = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          cp_target = &state->user_records[i]; break;
        }
      }
      if (!cp_target) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      snprintf(cp_target->password, sizeof(cp_target->password), "%s", arg2);
      cp_target->timestamp = time(NULL);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Password changed for %s\r\n", nick, arg1);

    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Admin commands: die, jump, op, join, part, "
                   "status, givenick, chnick, +server, -server, admins, opers, "
                   "+admin, -admin, +oper, -oper, +usermask, -usermask, chpass, "
                   "match, botpass, +bot, -bot, "
                   "+hub, -hub, sethubkey, setuuid, saveconf, setlog, getlog, "
                   "update, help\r\n",
                   nick);
      } else {
        if (strcasecmp(arg1, "die") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: die - Kills the bot process.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "jump") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: jump [server] - Jump to the next IRC server, "
              "or to a specific server by hostname (port-independent match).\r\n",
              nick);
        } else if (strcasecmp(arg1, "op") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: op <#channel> - Get operator status "
                     "on a channel.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "status") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: status - Show bot status.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "givenick") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: givenick - Temporarily changes the bot nick "
              "to an alternate. Will try to regain primary nick after 20 "
              "seconds until it accomplishes the task.\r\n",
              nick);
        } else if (strcasecmp(arg1, "chnick") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: chnick <oldnick> <newnick> - Renames "
                     "a bot, admin, or oper. Nicks must be unique across all types. "
                     "For bots, propagates the change via hub mesh.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "+server") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +server <irc.network.net:6667> - Add "
                     "another irc server to the bot's server list. Port not "
                     "required.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "-server") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -server <irc.network.net:6667> - "
                     "Removes a server from the bot's server list. Specify "
                     "server as it is listed in 'status' command.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "admins") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: admins - List all admins.\r\n", nick);
        } else if (strcasecmp(arg1, "opers") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: opers - List all opers.\r\n", nick);
        } else if (strcasecmp(arg1, "+admin") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +admin <name> <password> <mask> - "
                     "Add a named admin with first usermask. Name must be unique across admins and opers.\r\n", nick);
        } else if (strcasecmp(arg1, "-admin") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -admin <name> - Remove admin and all their masks.\r\n", nick);
        } else if (strcasecmp(arg1, "+oper") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +oper <name> <password> <mask> - "
                     "Add a named oper with first usermask.\r\n", nick);
        } else if (strcasecmp(arg1, "-oper") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -oper <name> - Remove oper and all their masks.\r\n", nick);
        } else if (strcasecmp(arg1, "+usermask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +usermask <name> <mask> - Add a usermask to admin or oper.\r\n", nick);
        } else if (strcasecmp(arg1, "-usermask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -usermask <name> <mask> - Remove a specific usermask from admin or oper.\r\n", nick);
        } else if (strcasecmp(arg1, "chpass") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: chpass <name> <newpassword> - Change password for named admin or oper. "
                     "Opers may only change their own password.\r\n", nick);
        } else if (strcasecmp(arg1, "match") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: match <name|*> - Show all records for a user, or * for all users.\r\n", nick);
        } else if (strcasecmp(arg1, "botpass") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: botpass <password> - Creates a bot "
                     "password that bots use to communicate with each other. "
                     "This password is used in all bot communication with "
                     "known bots matching a stored usermask.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "+bot") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: +bot <nick*!*user@hostmask.com> - Adds a "
              "bot mask for secure bot communication. The usermask should be "
              "reflective of potential nick changes.\r\n",
              nick);
        } else if (strcasecmp(arg1, "-bot") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -bot <nick*!*user@hostmask.com> - "
                     "Removes a bot from the known bot list as shown in the "
                     "'status' command.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "saveconf") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: saveconf - Immediately save config "
                     "file.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "setlog") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: setlog <loglevel> - Set loglevel for "
                     "output to a log file. 0=NONE,15=INFO,63=DEBUG.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "getlog") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: getlog <loglevel> [lines]. Get "
                     "latest logs for requested loglevel. Levels are 'msg' "
                     "'ctcp' 'info' 'cmd' 'raw' 'debug'. Default number of "
                     "lines: %d. Max number of lines: %d.\r\n",
                     nick, DEFAULT_LOG_LINES, MAX_LOG_LINES);
        } else if (strcasecmp(arg1, "update") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: update without argument shows "
                     "available versions. "
                     "Run with update <ver> to download/compile/and update bot "
                     "binary.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "join") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: join <#channel> - Joins a channel.\r\n",
              nick);
        } else if (strcasecmp(arg1, "part") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: part <#channel> - Parts a channel.\r\n",
              nick);
        } else if (strcasecmp(arg1, "+hub") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: +hub <ip:port> - Add a Hub server.\r\n",
              nick);
        } else if (strcasecmp(arg1, "sethubkey") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: sethubkey <88-char-b64> - Set Curve25519 key from hub admin.\r\n",
              nick);
        } else if (strcasecmp(arg1, "setuuid") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: setuuid <uuid> - Set the UUID "
                     "identifier for HUB connections. Expected: "
                     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.\r\n",
                     nick);
        } else {
          irc_printf(state,
                     "PRIVMSG %s :No help available for command '%s'.\r\n",
                     nick, arg1);
        }
      }
    }

  } else if (is_op) {
    log_message(L_CMD, state, "[CMD_OP] Op command from %s: %s %s\n", user_host,
                command, (arg1 ? arg1 : ""));
    if (strcasecmp(command, "op") == 0 && arg1) {
      char *saveptr_op;
      char *op_arg1 = strtok_r(arg1, " ", &saveptr_op);
      if (op_arg1)
        irc_printf(state, "MODE %s +o %s\r\n", op_arg1, nick);
    } else if (strcasecmp(command, "chpass") == 0) {
      /* Opers can only change their own password */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chpass <yourname> <newpassword>\r\n", nick); return;
      }
      if (!auth_user || strcasecmp(auth_user->name, arg1) != 0) {
        irc_printf(state, "PRIVMSG %s :Error: opers may only change their own password.\r\n", nick); return;
      }
      snprintf(auth_user->password, sizeof(auth_user->password), "%s", arg2);
      auth_user->timestamp = time(NULL);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Your password has been changed.\r\n", nick);
    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Oper commands: op, chpass, help\r\n", nick);
      } else {
        if (strcasecmp(arg1, "op") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: op <#channel> - Get operator status on a channel.\r\n", nick);
        } else if (strcasecmp(arg1, "chpass") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: chpass <yourname> <newpassword> - Change your own password.\r\n", nick);
        } else if (strcasecmp(arg1, "help") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: help [command] - Show available commands.\r\n", nick);
        } else {
          irc_printf(state, "PRIVMSG %s :No help available for command '%s'.\r\n", nick, arg1);
        }
      }
    }
  }
}
