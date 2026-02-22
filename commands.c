#include <ctype.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

unsigned char *base64_decode(const char *input, int *out_len);
// static int base64_decode(const char *input, unsigned char **output) {
//   BIO *b64 = BIO_new(BIO_f_base64());
//   BIO *bio = BIO_new_mem_buf((void *)input, -1);
//   bio = BIO_push(b64, bio);
//   BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
//   int input_len = strlen(input);
//   *output = (unsigned char *)malloc(input_len);
//   if (!*output) {
//     BIO_free_all(bio);
//     return 0;
//   }
//   int decoded_len = BIO_read(bio, *output, input_len);
//   BIO_free_all(bio);
//   return decoded_len;
// }
#ifndef _GNU_SOURCE
static void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen) {
  if (needlelen == 0)
    return (void *)haystack;
  if (haystacklen < needlelen)
    return NULL;

  const unsigned char *h = (const unsigned char *)haystack;
  const unsigned char *n = (const unsigned char *)needle;

  for (size_t i = 0; i <= haystacklen - needlelen; i++) {
    if (memcmp(h + i, n, needlelen) == 0) {
      return (void *)(h + i);
    }
  }
  return NULL;
}
#endif

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
    strncpy(message_copy_bot, message, sizeof(message_copy_bot) - 1);
    message_copy_bot[sizeof(message_copy_bot) - 1] = '\0';

    char *saveptr_enc;
    char *encoded_ciphertext = strtok_r(message_copy_bot, ":", &saveptr_enc);
    char *encoded_tag = strtok_r(NULL, "", &saveptr_enc);

    if (encoded_ciphertext && encoded_tag) {
      unsigned char *decoded_data = NULL;
      unsigned char *tag = NULL;
      int decoded_len = 0;
      int tag_len = 0;

      // 1. Capture the returned pointer into our variables
      // 2. Pass the address of the integer lengths (&decoded_len)
      decoded_data = base64_decode(encoded_ciphertext, &decoded_len);
      tag = base64_decode(encoded_tag, &tag_len);

      // Verify both decodes succeeded and meet size requirements
      if (decoded_data && tag && decoded_len > (SALT_SIZE + GCM_IV_LEN) &&
          tag_len == GCM_TAG_LEN) {
        unsigned char salt[SALT_SIZE];
        memcpy(salt, decoded_data, SALT_SIZE);

        unsigned char key[32];
        EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                       (const unsigned char *)state->bot_comm_pass,
                       strlen(state->bot_comm_pass), 1, key, NULL);

        unsigned char *ciphertext_ptr = decoded_data + SALT_SIZE;
        int ciphertext_len = decoded_len - SALT_SIZE;

        unsigned char *decrypted_data = malloc(ciphertext_len + 1);
        if (decrypted_data) {
          int decrypted_len = crypto_aes_gcm_decrypt(
              ciphertext_ptr, ciphertext_len, key, decrypted_data, tag);

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
                             strcasecmp(bot_command, "INVITE") == 0 &&
                             bot_arg1) {
                    /* arg1 = #channel, arg2 = nick_to_invite */
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
          free(decrypted_data);
        }
      }

      // Cleanup base64 buffers
      if (decoded_data)
        free(decoded_data);
      if (tag)
        free(tag);
    }
  }
  /* --- Block 2: Admin/Op Logic --- */
  char message_copy[MAX_BUFFER];
  strncpy(message_copy, message, sizeof(message_copy) - 1);
  message_copy[sizeof(message_copy) - 1] = '\0';

  char *saveptr_adm;
  char *auth_token = strtok_r(message_copy, " ", &saveptr_adm);
  if (!auth_token)
    return;

  char *saveptr_token;
  char *nonce_str = strtok_r(auth_token, ":", &saveptr_token);
  char *hash_str = strtok_r(NULL, "", &saveptr_token);

  if (!nonce_str || !hash_str)
    return;

  char *command = strtok_r(NULL, " ", &saveptr_adm);
  if (!command)
    return;
  char *arg1 = strtok_r(NULL, " ", &saveptr_adm);
  char *arg2 = strtok_r(NULL, " ", &saveptr_adm);

  log_message(L_DEBUG, state,
              "[CMD_DEBUG] Parsed: Cmd='%s' Arg1='%s' Nonce='%s'\n", command,
              (arg1 ? arg1 : "NULL"), nonce_str);

  bool is_admin = false;
  bool is_op = false;

  if (auth_check_hostmask(state, user_host)) {
    if (auth_verify_password(state, nonce_str, hash_str, state->bot_pass)) {
      is_admin = true;
    }
  }

  if (!is_admin) {
    log_message(L_CMD, state, "[CMD_DEBUG] Not Admin. Attempting Op Auth...\n");
    if (auth_verify_op_command(state, user_host, nonce_str, hash_str)) {
      is_op = true;
    } else {
      log_message(L_CMD, state, "[CMD_DEBUG] Op Auth returned FALSE.\n");
    }
  }

  if (is_admin) {
    log_message(L_CMD, state, "[CMD_ADMIN] Executing Admin Command...\n");

    if (strcasecmp(command, "die") == 0) {
      irc_printf(state, "QUIT :Sayonara.\r\n");
      state->status |= S_DIE;
    } else if (strcasecmp(command, "jump") == 0) {
      irc_printf(state, "QUIT :Jumping servers...\r\n");
      irc_disconnect(state);
    } else if (strcasecmp(command, "join") == 0) {
      char channel_name[MAX_CHAN];
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: join <#channel>\r\n", nick);
        return;
      }
      if (arg1[0] == '#') {
        strncpy(channel_name, arg1, sizeof(channel_name) - 1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      channel_name[sizeof(channel_name) - 1] = '\0';

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
          strncpy(c->key, arg2, MAX_KEY - 1);
        c->is_managed = true;      // Mark as managed for syncing
        c->timestamp = time(NULL); // Set timestamp for sync
        log_message(L_DEBUG, state, "[JOIN] Channel %s: re-enabled ts=%ld\n",
                    channel_name, (long)c->timestamp);
      }
      config_write(state, state->startup_password);
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
        strncpy(channel_name, arg1, sizeof(channel_name) - 1);
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
        config_write(state, state->startup_password);
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
          if (sscanf(state->trusted_bots[i], "%63[^!]", tb_nick) == 1) {
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
      strncpy(state->bot_comm_pass, arg1, MAX_PASS - 1);
      state->bot_comm_pass_ts = time(NULL);
      config_write(state, state->startup_password);
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
        state->trusted_bots[state->trusted_bot_count++] = strdup(arg1);
        state->trusted_bots[state->trusted_bot_count] = NULL;
        config_write(state, state->startup_password);
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
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Removed trusted bot: %s\r\n", nick,
                   arg1);
      }
    } else if (strcasecmp(command, "status") == 0) {
      char line_buffer[MAX_BUFFER];
      char uptime_str[128];
      const char *conn_status =
          (state->status & S_CONNECTED) ? "CONNECTED" : "DISCONNECTED";
      const char *tls_status = state->is_ssl ? "YES" : "NO";
      const char *server_to_display =
          (state->actual_server_name[0] != '\0')
              ? state->actual_server_name
              : (state->current_server_index > 0
                     ? state->server_list[state->current_server_index - 1]
                     : "N/A");

      if (state->connection_time > 0 && (state->status & S_CONNECTED)) {
        long uptime_seconds = time(NULL) - state->connection_time;
        snprintf(uptime_str, sizeof(uptime_str), "%ldd %ldh %ldm %lds",
                 uptime_seconds / 86400, (uptime_seconds % 86400) / 3600,
                 (uptime_seconds % 3600) / 60, uptime_seconds % 60);
      } else {
        strncpy(uptime_str, "N/A", sizeof(uptime_str) - 1);
        uptime_str[sizeof(uptime_str) - 1] = '\0';
      }

      irc_printf(state, "PRIVMSG %s :--- Bot Status :: %s %s ---\r\n", nick,
                 BOT_NAME, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s : Nick: %s (Target: %s)\r\n", nick,
                 state->current_nick, state->target_nick);
      irc_printf(state, "PRIVMSG %s : Server: %s (%s)\r\n", nick,
                 server_to_display, conn_status);
      irc_printf(state, "PRIVMSG %s : TLS Active: %s\r\n", nick, tls_status);
      irc_printf(state, "PRIVMSG %s : Uptime: %s\r\n", nick, uptime_str);
      irc_printf(state, "PRIVMSG %s : UUID: %s\r\n", nick,
                 (state->bot_uuid[0] ? state->bot_uuid : "None (Standalone)"));
      if (state->hub_connected && state->current_hub[0]) {
        irc_printf(state, "PRIVMSG %s : Hub Status: CONNECTED TO %s (FD: %d)\r\n",
                   nick, state->current_hub, state->hub_fd);
      } else {
        irc_printf(state, "PRIVMSG %s : Hub Status: %s (FD: %d)\r\n", nick,
                   (state->hub_connected ? "CONNECTED" : "DISCONNECTED"),
                   state->hub_fd);
      }

      int max_width = 0;
      for (int i = 0; i < state->server_count; i++) {
        int len = strlen(state->server_list[i]);
        if (len > max_width)
          max_width = len;
      }
      for (int i = 0; i < state->mask_count; i++) {
        int len = strlen(state->auth_masks[i].mask);
        if (len > max_width)
          max_width = len;
      }
      if (max_width < 15)
        max_width = 15;
      max_width += 2;

      snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
               "--- Servers", "Channels ---");
      irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);

      int max_rows = (state->server_count > state->chan_count)
                         ? state->server_count
                         : state->chan_count;
      chan_t *current_chan = state->chanlist;

      for (int i = 0; i < max_rows; i++) {
        char server_part[128] = "";
        char chan_part[128] = "";

        if (i < state->server_count)
          strncpy(server_part, state->server_list[i], sizeof(server_part) - 1);

        // Skip non-managed channels
        while (current_chan && !current_chan->is_managed) {
          current_chan = current_chan->next;
        }

        if (current_chan) {
          bool am_i_opped = false;
          for (int j = 0; j < current_chan->roster_count; j++) {
            if (strcasecmp(current_chan->roster[j].nick, state->current_nick) ==
                    0 &&
                current_chan->roster[j].is_op) {
              am_i_opped = true;
              break;
            }
          }
          const char *op_prefix = am_i_opped ? "@" : "";
          const char *status_str =
              (current_chan->status == C_IN) ? "IN" : "OUT";

          if (current_chan->key[0] != '\0') {
            snprintf(chan_part, sizeof(chan_part), "%s%s (Key: %s) (%s)",
                     op_prefix, current_chan->name, current_chan->key,
                     status_str);
          } else {
            snprintf(chan_part, sizeof(chan_part), "%s%s (%s)", op_prefix,
                     current_chan->name, status_str);
          }
          current_chan = current_chan->next;
        }
        // Only print if there's content
        if (server_part[0] != '\0' || chan_part[0] != '\0') {
          snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
                   server_part, chan_part);
          irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);
        }
      }

      snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
               "--- Admin Masks", "Op Masks ---");
      irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);

      max_rows = (state->mask_count > state->op_mask_count)
                     ? state->mask_count
                     : state->op_mask_count;

      for (int i = 0; i < max_rows; i++) {
        char admin_part[128] = "";
        char op_part[256] = "";

        if (i < state->mask_count) {
          snprintf(admin_part, sizeof(admin_part), "%s",
                   state->auth_masks[i].mask);
        }

        if (i < state->op_mask_count) {
          snprintf(op_part, sizeof(op_part), "%.*s", 50,
                   state->op_masks[i].mask);
        }

        snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
                 admin_part, op_part);
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);
      }

      irc_printf(state, "PRIVMSG %s :--- Trusted Bots ---\r\n", nick);
      for (int i = 0; i < state->trusted_bot_count; i++) {
        // Extract just the hostmask from format: hostmask|uuid|timestamp
        char hostmask[128];
        if (sscanf(state->trusted_bots[i], "%127[^|]", hostmask) == 1) {
          irc_printf(state, "PRIVMSG %s : - %s\r\n", nick, hostmask);
        } else {
          irc_printf(state, "PRIVMSG %s : - %s\r\n", nick,
                     state->trusted_bots[i]);
        }
      }

      irc_printf(state, "PRIVMSG %s :--- Configured Hubs ---\r\n", nick);
      for (int i = 0; i < state->hub_count; i++)
        irc_printf(state, "PRIVMSG %s : - %s\r\n", nick, state->hub_list[i]);

      size_t footer_len = (size_t)max_width + 40;
      if (footer_len > sizeof(line_buffer) - 1)
        footer_len = sizeof(line_buffer) - 1;
      memset(line_buffer, '-', footer_len);
      line_buffer[footer_len] = '\0';
      irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);
    } else if (strcasecmp(command, "givenick") == 0) {
      irc_printf(state,
                 "PRIVMSG %s :You have about %d seconds to retrieve.\r\n", nick,
                 NICK_TAKE_TIME);
      irc_generate_new_nick(state);
      state->nick_release_time = time(NULL);
    } else if (strcasecmp(command, "setnick") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: setnick <nickname>\r\n", nick);
        return;
      }
      if (strlen(arg1) >= MAX_NICK) {
        irc_printf(
            state,
            "PRIVMSG %s :Error: Nickname is too long (max %d chars).\r\n", nick,
            MAX_NICK - 1);
      } else {
        strncpy(state->target_nick, arg1, MAX_NICK - 1);
        state->target_nick[MAX_NICK - 1] = '\0';
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Target nickname changed to '%s' and saved.\r\n",
                   nick, state->target_nick);
      }
    } else if (strcasecmp(command, "saveconf") == 0) {
      config_write(state, state->startup_password);
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
        config_write(state, state->startup_password);
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
    } else if (strcasecmp(command, "join") == 0) {
      char channel_name[MAX_CHAN];
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: join <#channel>\r\n", nick);
        return;
      }
      if (arg1[0] == '#') {
        strncpy(channel_name, arg1, sizeof(channel_name) - 1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      channel_name[sizeof(channel_name) - 1] = '\0';

      chan_t *existing = channel_find(state, channel_name);
      if (existing) {
        if (!existing->is_managed) {
          // Reactivate
          existing->is_managed = true;
          existing->timestamp = time(NULL);
          if (arg2)
            strncpy(existing->key, arg2, MAX_KEY - 1);
          config_write(state, state->startup_password);
          irc_printf(state,
                     "PRIVMSG %s :Re-enabled management for channel %s and "
                     "saved config.\r\n",
                     nick, channel_name);
          irc_printf(state, "JOIN %s %s\r\n", channel_name, (arg2 ? arg2 : ""));
        } else {
          // Already managed
          irc_printf(
              state,
              "PRIVMSG %s :Error: Channel %s is already in my active list.\r\n",
              nick, channel_name);
        }
      } else {
        // New Add
        chan_t *c = channel_add(state, channel_name);
        if (c) {
          if (arg2)
            strncpy(c->key, arg2, MAX_KEY - 1);
          c->is_managed = true; // Mark as managed
          c->timestamp = time(NULL);
          config_write(state, state->startup_password);
          irc_printf(state,
                     "PRIVMSG %s :Added channel %s and saved config.\r\n", nick,
                     channel_name);
          irc_printf(state, "JOIN %s %s\r\n", channel_name, (arg2 ? arg2 : ""));
        }
      }
    } else if (strcasecmp(command, "+adminmask") == 0) {
      if (!arg1) {
        irc_printf(
            state,
            "PRIVMSG %s :Syntax: +adminmask <nick*!*user@hostmask.com>\r\n",
            nick);
        return;
      }

      int found_idx = -1;
      for (int i = 0; i < state->mask_count; i++) {
        if (strcasecmp(state->auth_masks[i].mask, arg1) == 0) {
          found_idx = i;
          break;
        }
      }

      if (found_idx != -1) {
        if (!state->auth_masks[found_idx].is_managed) {
          // Reactivate
          state->auth_masks[found_idx].is_managed = true;
          state->auth_masks[found_idx].timestamp = time(NULL);
          config_write(state, state->startup_password);
          irc_printf(state, "PRIVMSG %s :Re-enabled admin mask: %s\r\n", nick,
                     arg1);
        } else {
          irc_printf(state,
                     "PRIVMSG %s :Error: Admin mask '%s' already exists and is "
                     "active.\r\n",
                     nick, arg1);
        }
      } else {
        if (state->mask_count < MAX_MASKS) {
          strncpy(state->auth_masks[state->mask_count].mask, arg1,
                  MAX_MASK_LEN - 1);
          state->auth_masks[state->mask_count].mask[MAX_MASK_LEN - 1] = '\0';
          state->auth_masks[state->mask_count].is_managed = true;
          state->auth_masks[state->mask_count].timestamp = time(NULL);
          state->mask_count++;
          config_write(state, state->startup_password);
          irc_printf(state, "PRIVMSG %s :Added admin mask: %s\r\n", nick, arg1);
        } else {
          irc_printf(state, "PRIVMSG %s :Error: Mask list full.\r\n", nick);
        }
      }
    } else if (strcasecmp(command, "-adminmask") == 0) {
      if (!arg1) {
        irc_printf(
            state,
            "PRIVMSG %s :Syntax: -adminmask <nick*!*user@hostmask.com>\r\n",
            nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->mask_count; i++) {
        if (strcasecmp(state->auth_masks[i].mask, arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        // Soft delete
        state->auth_masks[found_index].is_managed = false;
        state->auth_masks[found_index].timestamp = time(NULL);
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Disabled admin mask (Soft Delete): %s\r\n",
                   nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Mask not found.\r\n", nick);
      }
    } else if (strcasecmp(command, "adminpass") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: adminpass <password>\r\n", nick);
        return;
      }
      if (strlen(arg1) > 0) {
        strncpy(state->bot_pass, arg1, MAX_PASS - 1);
        state->bot_pass_ts = time(NULL);
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Admin password has been changed and saved.\r\n",
                   nick);
      } else
        irc_printf(state, "PRIVMSG %s :Error: Password cannot be empty.\r\n",
                   nick);
    } else if (strcasecmp(command, "+oper") == 0) {
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: +oper <mask> <password>\r\n",
                   nick);
        return;
      }

      int found_idx = -1;
      for (int i = 0; i < state->op_mask_count; i++) {
        if (strcasecmp(state->op_masks[i].mask, arg1) == 0) {
          found_idx = i;
          break;
        }
      }

      if (found_idx != -1) {
        if (!state->op_masks[found_idx].is_managed) {
          // Reactivate
          state->op_masks[found_idx].is_managed = true;
          state->op_masks[found_idx].timestamp = time(NULL);
          strncpy(state->op_masks[found_idx].password, arg2, MAX_PASS - 1);
          config_write(state, state->startup_password);
          irc_printf(state, "PRIVMSG %s :Re-enabled op mask for %s.\r\n", nick,
                     arg1);
        } else {
          irc_printf(state,
                     "PRIVMSG %s :Error: Operator mask '%s' already exists and "
                     "is active.\r\n",
                     nick, arg1);
        }
      } else {
        if (state->op_mask_count < MAX_OP_MASKS) {
          strncpy(state->op_masks[state->op_mask_count].mask, arg1,
                  MAX_MASK_LEN - 1);
          strncpy(state->op_masks[state->op_mask_count].password, arg2,
                  MAX_PASS - 1);
          state->op_masks[state->op_mask_count].is_managed = true;
          state->op_masks[state->op_mask_count].timestamp = time(NULL);
          state->op_mask_count++;
          config_write(state, state->startup_password);
          irc_printf(state, "PRIVMSG %s :Added op mask for %s.\r\n", nick,
                     arg1);
        } else {
          irc_printf(state, "PRIVMSG %s :Error: Op list full.\r\n", nick);
        }
      }
    } else if (strcasecmp(command, "-oper") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -oper <mask>\r\n", nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->op_mask_count; i++) {
        if (strcasecmp(state->op_masks[i].mask, arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        // Soft delete
        state->op_masks[found_index].is_managed = false;
        state->op_masks[found_index].timestamp = time(NULL);
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Disabled op mask (Soft Delete) for %s.\r\n",
                   nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Mask not found.\r\n", nick);
      }
    } else if (strcasecmp(command, "+server") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +server <irc.server.net:6667>\r\n",
                   nick);
        return;
      }
      if (state->server_count < MAX_SERVERS) {
        state->server_list[state->server_count++] = strdup(arg1);
        state->server_list[state->server_count] = NULL;
        config_write(state, state->startup_password);
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
        config_write(state, state->startup_password);
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
        state->hub_list[state->hub_count++] = strdup(arg1);
        config_write(state, state->startup_password);
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
        config_write(state, state->startup_password);
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
                   "PRIVMSG %s :Syntax: sethubkey N/TOTAL:data or RESET\r\n",
                   nick);
      } else if (strcasecmp(arg1, "RESET") == 0) {
        memset(state->hub_key_parts, 0, sizeof(state->hub_key_parts));
        state->hub_key_parts_received = 0;
        state->hub_key_parts_expected = 0;
        state->hub_key[0] = '\0';
        irc_printf(state, "PRIVMSG %s :Multi-part buffer cleared.\r\n", nick);
      } else {
        char *slash = strchr(arg1, '/');
        char *colon = strchr(arg1, ':');

        if (slash && colon && slash < colon) {
          // Multi-part mode
          int part_num = atoi(arg1);
          int total_parts = atoi(slash + 1);
          char *data = colon + 1;

          if (part_num >= 1 && part_num <= 16 && total_parts >= 1 &&
              total_parts <= 16) {
            if (state->hub_key_parts_expected == 0) {
              state->hub_key_parts_expected = total_parts;
            }

            int idx = part_num - 1;
            strncpy(state->hub_key_parts[idx], data, 255);
            state->hub_key_parts[idx][255] = '\0';
            state->hub_key_parts_received |= (1 << idx);

            uint16_t expected_mask = (1 << total_parts) - 1;

            if ((state->hub_key_parts_received & expected_mask) ==
                expected_mask) {
              // All parts received - assemble
              state->hub_key[0] = '\0';
              for (int i = 0; i < total_parts; i++) {
                strncat(state->hub_key, state->hub_key_parts[i],
                        sizeof(state->hub_key) - strlen(state->hub_key) - 1);
              }

              // Validate: Decode base64 and check for PEM headers
              int pem_len = 0;
              unsigned char *pem_data = base64_decode(state->hub_key, &pem_len);

              if (pem_data && pem_len > 0) {
                // Check if it contains PEM header
                bool valid_pem =
                    (memmem(pem_data, pem_len, "-----BEGIN PRIVATE KEY-----",
                            27) != NULL ||
                     memmem(pem_data, pem_len,
                            "-----BEGIN RSA PRIVATE KEY-----", 31) != NULL);

                if (valid_pem) {
                  // Valid! Save and reconnect
                  state->hub_key_parts_received = 0;
                  state->hub_key_parts_expected = 0;
                  memset(state->hub_key_parts, 0, sizeof(state->hub_key_parts));

                  config_write(state, state->startup_password);
                  irc_printf(state,
                             "PRIVMSG %s :✓ Complete! Valid PEM key received "
                             "(%d bytes). Reconnecting...\r\n",
                             nick, pem_len);

                  free(pem_data);

                  if (state->hub_fd != -1) {
                    close(state->hub_fd);
                    state->hub_fd = -1;
                  }
                  state->last_hub_connect_attempt = 0;
                  hub_client_connect(state);
                } else {
                  irc_printf(state,
                             "PRIVMSG %s :ERROR: Decoded data is not a valid "
                             "PEM private key. Use RESET.\r\n",
                             nick);
                  free(pem_data);
                }
              } else {
                irc_printf(state,
                           "PRIVMSG %s :ERROR: Invalid base64 encoding. Use "
                           "RESET and try again.\r\n",
                           nick);
                if (pem_data)
                  free(pem_data);
              }
            } else {
              // Still waiting for more parts
              int received_count = 0;
              for (int i = 0; i < total_parts; i++) {
                if (state->hub_key_parts_received & (1 << i))
                  received_count++;
              }
              irc_printf(
                  state,
                  "PRIVMSG %s :Part %d/%d received (%d/%d complete).\r\n", nick,
                  part_num, total_parts, received_count, total_parts);
            }
          } else {
            irc_printf(state,
                       "PRIVMSG %s :ERROR: Invalid part number or total. Must "
                       "be 1-16.\r\n",
                       nick);
          }
        } else {
          // Single-part mode (legacy)
          // Validate base64 and PEM format
          int pem_len = 0;
          unsigned char *pem_data = base64_decode(arg1, &pem_len);

          if (pem_data && pem_len > 0) {
            bool valid_pem =
                (memmem(pem_data, pem_len, "-----BEGIN PRIVATE KEY-----", 27) !=
                     NULL ||
                 memmem(pem_data, pem_len, "-----BEGIN RSA PRIVATE KEY-----",
                        31) != NULL);

            if (valid_pem) {
              strncpy(state->hub_key, arg1, sizeof(state->hub_key) - 1);
              state->hub_key[sizeof(state->hub_key) - 1] = '\0';

              memset(state->hub_key_parts, 0, sizeof(state->hub_key_parts));
              state->hub_key_parts_received = 0;
              state->hub_key_parts_expected = 0;

              config_write(state, state->startup_password);
              irc_printf(state,
                         "PRIVMSG %s :✓ Valid PEM key set (%d bytes). "
                         "Reconnecting...\r\n",
                         nick, pem_len);

              free(pem_data);

              if (state->hub_fd != -1) {
                close(state->hub_fd);
                state->hub_fd = -1;
              }
              state->last_hub_connect_attempt = 0;
              hub_client_connect(state);
            } else {
              irc_printf(state,
                         "PRIVMSG %s :ERROR: Not a valid PEM private key.\r\n",
                         nick);
              free(pem_data);
            }
          } else {
            irc_printf(state, "PRIVMSG %s :ERROR: Invalid base64 encoding.\r\n",
                       nick);
            if (pem_data)
              free(pem_data);
          }
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
      strncpy(state->bot_uuid, sanitized, sizeof(state->bot_uuid) - 1);
      state->bot_uuid[sizeof(state->bot_uuid) - 1] = 0;
      config_write(state, state->startup_password);
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
    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Admin commands: die, jump, op, join, part, "
                   "status, givenick, setnick, +server, -server, adminpass, "
                   "+adminmask, -adminmask, +oper, -oper, botpass, +bot, -bot, "
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
              "PRIVMSG %s :Syntax: jump - Jump to the next irc server.\r\n",
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
        } else if (strcasecmp(arg1, "setnick") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: setnick <nickname> - Changes the "
                     "primary nickname of the bot.\r\n",
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
        } else if (strcasecmp(arg1, "adminpass") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: adminpass <password> - Changes the "
                     "admin password. Rembember that your auth hash creation "
                     "must be updated to use the new password as well.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "+adminmask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +adminmask "
                     "<nick*!*user@hostmask.com> - Adds a usermask to the "
                     "allowed admin hostmask list. Asterisks are accepted.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "-adminmask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -adminmask "
                     "<nick*!*user@hostmask.com> - Removes a usermask from the "
                     "allowed admin hostmask list. Specifiy hostmask to be "
                     "removed as shown from the 'status' command.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "+oper") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: +oper <nick*!*user@hostmask.com> <password> "
              " - Add an operator (can only request ops from bot). Each "
              "operator is stored with a hostmask and password.\r\n",
              nick);
        } else if (strcasecmp(arg1, "-oper") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -oper <nick*!*user@hostmask.com>  - "
                     "Removes an operator from the operator list. Specify the "
                     "operator usermask to remove as shown from the 'status' "
                     "command. Password not necessary in this command.\r\n",
                     nick);
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
              "PRIVMSG %s :Syntax: sethubkey <key> - Set the Identity Key.\r\n",
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
    }
  }
}
