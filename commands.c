#include <ctype.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bot.h"

static int base64_decode(const char *input, unsigned char **output) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new_mem_buf((void *)input, -1);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  int input_len = strlen(input);
  *output = (unsigned char *)malloc(input_len);
  if (!*output) {
    BIO_free_all(bio);
    return 0;
  }
  int decoded_len = BIO_read(bio, *output, input_len);
  BIO_free_all(bio);
  return decoded_len;
}

void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message) {
  if (strcasecmp(dest, state->current_nick) != 0) return;

  char user_host[256];
  snprintf(user_host, sizeof(user_host), "%s!%s@%s", nick, user, host);

  log_message(L_MSG, state, "[MSG] (%s): %s\n", user_host, message);

  if (auth_is_trusted_bot(state, user_host)) {
    char message_copy_bot[MAX_BUFFER];
    strncpy(message_copy_bot, message, sizeof(message_copy_bot) - 1);
    message_copy_bot[sizeof(message_copy_bot) - 1] = '\0';

    char *saveptr_enc;
    char *encoded_ciphertext = strtok_r(message_copy_bot, ":", &saveptr_enc);
    char *encoded_tag = strtok_r(NULL, "", &saveptr_enc);

    if (!encoded_ciphertext || !encoded_tag) return;

    unsigned char *ciphertext = NULL;
    unsigned char *tag = NULL;
    int ciphertext_len = base64_decode(encoded_ciphertext, &ciphertext);
    int tag_len = base64_decode(encoded_tag, &tag);

    if (ciphertext_len > 0 && tag_len == GCM_TAG_LEN) {
      unsigned char key[32];
      EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), NULL,
                     (const unsigned char *)state->bot_comm_pass,
                     strlen(state->bot_comm_pass), 1, key, NULL);

      unsigned char *decrypted_data = malloc(ciphertext_len);
      int decrypted_len = crypto_aes_gcm_decrypt(ciphertext, ciphertext_len,
                                                 key, decrypted_data, tag);

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
              char *command = strtok_r(command_part, " ", &saveptr_cmd);
              char *arg1 = strtok_r(NULL, " ", &saveptr_cmd);
              if (command && strcasecmp(command, "OPME") == 0 && arg1) {
                irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
              }
            }
          }
        }
        free(decrypted_data);
      }
    }
    if (ciphertext) free(ciphertext);
    if (tag) free(tag);
  }

  char message_copy[MAX_BUFFER];
  strncpy(message_copy, message, sizeof(message_copy) - 1);
  message_copy[sizeof(message_copy) - 1] = '\0';

  char *saveptr_adm;
  char *password_attempt = strtok_r(message_copy, " ", &saveptr_adm);
  if (!password_attempt) return;
  char *command = strtok_r(NULL, " ", &saveptr_adm);
  if (!command) return;
  char *arg1 = strtok_r(NULL, " ", &saveptr_adm);
  char *arg2 = strtok_r(NULL, " ", &saveptr_adm);

  if (auth_check_hostmask(state, user_host) &&
      auth_verify_password(password_attempt, state->bot_pass)) {
    log_message(L_CMD, state, "[CMD_ADMIN] Admin command from %s: %s %s %s\n",
                user_host, command, (arg1 ? arg1 : ""), (arg2 ? arg2 : ""));

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

      if (channel_find(state, channel_name)) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Channel %s is already in my list.\r\n",
                   nick, channel_name);
        return;
      }

      chan_t *c = channel_add(state, channel_name);
      if (c && arg2) {
        strncpy(c->key, arg2, MAX_KEY - 1);
      }
      config_write(state, state->startup_password);
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
      if (channel_remove(state, arg1)) {
        irc_printf(state, "PART %s\r\n", channel_name);
        config_write(state, state->startup_password);
      }
    } else if (strcasecmp(command, "op") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: op <#channel>\r\n", nick);
        return;
      }
      irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
    } else if (strcasecmp(command, "botpass") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: botpass <password>\r\n", nick);
        return;
      }
      strncpy(state->bot_comm_pass, arg1, MAX_PASS - 1);
      config_write(state, state->startup_password);
      irc_printf(state,
                 "PRIVMSG %s :Bot communication password set and saved.\r\n",
                 nick);
    } else if (strcasecmp(command, "+bot") == 0) {
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

      int max_width = 0;
      for (int i = 0; i < state->server_count; i++) {
        int len = strlen(state->server_list[i]);
        if (len > max_width) max_width = len;
      }
      for (int i = 0; i < state->mask_count; i++) {
        int len = strlen(state->auth_masks[i]);
        if (len > max_width) max_width = len;
      }
      if (max_width < 15) max_width = 15;
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

        if (i < state->server_count) {
          strncpy(server_part, state->server_list[i], sizeof(server_part) - 1);
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
        snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
                 server_part, chan_part);
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);
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
          strncpy(admin_part, state->auth_masks[i], sizeof(admin_part) - 1);
        }
        if (i < state->op_mask_count) {
          snprintf(op_part, sizeof(op_part), "%.*s (Pass: %.*s)", 100,
                   state->op_masks[i].mask, 100, state->op_masks[i].password);
        }

        snprintf(line_buffer, sizeof(line_buffer), "%-*s | %s", max_width,
                 admin_part, op_part);
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, line_buffer);
      }

      irc_printf(state, "PRIVMSG %s :--- Trusted Bots (Botpass: %s) ---\r\n",
                 nick, state->bot_comm_pass);
      for (int i = 0; i < state->trusted_bot_count; i++) {
        irc_printf(state, "PRIVMSG %s : - %s\r\n", nick,
                   state->trusted_bots[i]);
      }

      size_t footer_len = (size_t)max_width + 40;
      if (footer_len > sizeof(line_buffer) - 1) {
        footer_len = sizeof(line_buffer) - 1;
      }
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
      for (int i = 0; arg1[i] != '\0'; i++) {
        if (!isdigit(arg1[i])) {
          is_valid_int = false;
          break;
        }
      }
      if (is_valid_int) {
        int new_level = atoi(arg1);
        state->log_type = (log_type_t)new_level;
        irc_printf(state, "PRIVMSG %s :Log level set to %d.\r\n", nick,
                   new_level);
        config_write(state, state->startup_password);
      } else {
        irc_printf(state,
                   "PRIVMSG %s :Invalid log level. Please provide a valid "
                   "integer.\r\n",
                   nick);
      }
    } else if (strcasecmp(command, "getlog") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: getlog <level> [lines]. Levels are "
                   "'msg' 'ctcp' 'info' 'cmd' 'raw' 'debug'. Default number of "
                   "lines: %d. Max number of lines: %d.\r\n",
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
        irc_printf(state,
                   "PRIVMSG %s :Error: Unknown log level '%s'. Available "
                   "levels are 'msg' 'ctcp' 'info' 'cmd' 'raw' 'debug'.\r\n",
                   nick, arg1);
        return;
      }

      int lines_to_show = DEFAULT_LOG_LINES;
      if (arg2) {
        lines_to_show = atoi(arg2);
        if (lines_to_show <= 0) lines_to_show = DEFAULT_LOG_LINES;
        if (lines_to_show > MAX_LOG_LINES) {
          irc_printf(state,
                     "PRIVMSG %s :Warning: Line count capped at %d to prevent "
                     "flooding.\r\n",
                     nick, MAX_LOG_LINES);
          lines_to_show = MAX_LOG_LINES;
        }
      }

      log_entry_t *matches[LOG_BUFFER_LINES];
      int matches_found = 0;

      log_buffer_t *buffer = &state->in_memory_logs[buffer_index];

      for (int i = 0; i < LOG_BUFFER_LINES; i++) {
        int idx = (buffer->log_idx + i) % LOG_BUFFER_LINES;
        log_entry_t *entry = &buffer->entries[idx];
        if (entry->line[0] != '\0') {
          matches[matches_found++] = entry;
        }
      }

      int lines_to_print =
          (matches_found < lines_to_show) ? matches_found : lines_to_show;
      int start_index = matches_found - lines_to_print;

      irc_printf(state,
                 "PRIVMSG %s :--- Start of Log (%s) - Showing last %d of %d "
                 "lines --- \r\n",
                 nick, arg1, lines_to_print, matches_found);

      struct timespec delay = {0, 250000000};
      nanosleep(&delay, NULL);

      for (int i = matches_found - 1; i >= start_index; i--) {
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, matches[i]->line);
        nanosleep(&delay, NULL);
      }
      irc_printf(state, "PRIVMSG %s :--- End of Log (%s) --- \r\n", nick, arg1);
    } else if (strcasecmp(command, "+adminmask") == 0) {
      if (!arg1) {
        irc_printf(
            state,
            "PRIVMSG %s :Syntax: +adminmask <nick*!*user@hostmask.com>\r\n",
            nick);
        return;
      }
      for (int i = 0; i < state->mask_count; i++) {
        if (strcasecmp(state->auth_masks[i], arg1) == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Error: Admin mask '%s' already exists.\r\n",
                     nick, arg1);
          return;
        }
      }
      if (state->mask_count < MAX_MASKS) {
        state->auth_masks[state->mask_count++] = strdup(arg1);
        state->auth_masks[state->mask_count] = NULL;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Added admin mask: %s\r\n", nick, arg1);
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
        if (strcasecmp(state->auth_masks[i], arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        free(state->auth_masks[found_index]);
        for (int i = found_index; i < state->mask_count - 1; i++) {
          state->auth_masks[i] = state->auth_masks[i + 1];
        }
        state->mask_count--;
        state->auth_masks[state->mask_count] = NULL;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Removed admin mask: %s\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "adminpass") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: adminpass <password>\r\n", nick);
        return;
      }
      if (strlen(arg1) > 0) {
        strncpy(state->bot_pass, arg1, MAX_PASS - 1);
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Admin password has been changed and saved.\r\n",
                   nick);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Password cannot be empty.\r\n",
                   nick);
      }
    } else if (strcasecmp(command, "+oper") == 0) {
      if (!arg1 || !arg2) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +oper <nick*!*user@hostmask.com> "
                   "<password>\r\n",
                   nick);
        return;
      }
      for (int i = 0; i < state->op_mask_count; i++) {
        if (strcasecmp(state->op_masks[i].mask, arg1) == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Error: Operator mask '%s' already exists.\r\n", nick,
              arg1);
          return;
        }
      }
      if (state->op_mask_count < MAX_OP_MASKS) {
        strncpy(state->op_masks[state->op_mask_count].mask, arg1,
                MAX_MASK_LEN - 1);
        strncpy(state->op_masks[state->op_mask_count].password, arg2,
                MAX_PASS - 1);
        state->op_mask_count++;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Added op mask for %s.\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "-oper") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: -oper <nick*!*user@hostmask.com>\r\n",
                   nick);
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
        for (int i = found_index; i < state->op_mask_count - 1; i++) {
          state->op_masks[i] = state->op_masks[i + 1];
        }
        state->op_mask_count--;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Removed op mask for %s.\r\n", nick,
                   arg1);
      }
    } else if (strcasecmp(command, "+server") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +server <irc.network.net:6667>\r\n",
                   nick);
        return;
      }
      if (state->server_count < MAX_SERVERS) {
        state->server_list[state->server_count++] = strdup(arg1);
        state->server_list[state->server_count] = NULL;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Added server '%s' and saved config.\r\n",
                   nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Server list is full.\r\n", nick);
      }
    } else if (strcasecmp(command, "-server") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: -server <irc.network.net:6667>\r\n",
                   nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->server_count; i++) {
        if (strcasecmp(state->server_list[i], arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        free(state->server_list[found_index]);
        for (int i = found_index; i < state->server_count - 1; i++) {
          state->server_list[i] = state->server_list[i + 1];
        }
        state->server_count--;
        state->server_list[state->server_count] = NULL;
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Removed server '%s' and saved config.\r\n",
                   nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Server not found in list.\r\n",
                   nick);
      }
    } else if (strcasecmp(command, "update") == 0) {
      if (arg1) {
        updater_perform_upgrade(state, nick, arg1);
      } else {
        updater_check_for_updates(state, nick);
      }
    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Admin commands: die, jump, op, join, part, "
                   "status, givenick, setnick, +server, -server, adminpass, "
                   "+adminmask, -adminmask, +oper, -oper, botpass, +bot, -bot, "
                   "saveconf, setlog, getlog, update, help\r\n",
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
        } else {
          irc_printf(state,
                     "PRIVMSG %s :No help available for command '%s'.\r\n",
                     nick, arg1);
        }
      }
    } else if (auth_verify_op_command(state, user_host, password_attempt)) {
      log_message(L_CMD, state, "[CMD_OP] Op command from %s: %s %s\n",
                  user_host, command, (arg1 ? arg1 : ""));

      if (strcasecmp(command, "op") == 0) {
        char *saveptr_op;
        char *op_arg1 = strtok_r(arg1, " ", &saveptr_op);
        if (op_arg1) {
          irc_printf(state, "MODE %s +o %s\r\n", op_arg1, nick);
        }
      }
    }
  }
}
