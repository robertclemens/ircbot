#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message) {
  if (strcasecmp(dest, state->current_nick) != 0) return;

  char user_host[256];
  snprintf(user_host, sizeof(user_host), "%s!%s@%s", nick, user, host);

  if (!auth_check_hostmask(state, user_host)) {
    log_message(L_CMD, state,
                "[FAIL] Denied command from unauthorized host: %s\n",
                user_host);
    return;
  }

  log_message(L_MSG, state, "[(msg)%s] %s\n", user_host, message);

  char message_copy[MAX_BUFFER];
  strncpy(message_copy, message, sizeof(message_copy) - 1);
  message_copy[sizeof(message_copy) - 1] = '\0';
  char *password_attempt = strtok(message_copy, " ");

  if (!password_attempt) return;
  char *command = strtok(NULL, " ");
  if (!command) return;
  char *arg1 = strtok(NULL, " ");
  char *arg2 = strtok(NULL, " ");

  if (auth_verify_password(password_attempt, state->bot_pass)) {
    log_message(L_CMD, state, "[CMD] Admin command from %s: %s\n", user_host,
                command);
    if (strcasecmp(command, "die") == 0) {
      irc_printf(state, "QUIT :Sayonara.\r\n");
      state->status |= S_DIE;
    } else if (strcasecmp(command, "jump") == 0) {
      irc_printf(state, "QUIT :Jumping servers...\r\n");
      irc_disconnect(state);
    } else if (strcasecmp(command, "op") == 0 && arg1) {
      irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
    } else if (strcasecmp(command, "join") == 0 && arg1) {
      char channel_name[MAX_CHAN];
      if (arg1[0] == '#') {
        strncpy(channel_name, arg1, sizeof(channel_name) - 1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      if (state->ignored_default_channel[0] != '\0' &&
          strcasecmp(arg1, DEFAULT_CHANNEL) == 0) {
        state->ignored_default_channel[0] = '\0';
        irc_printf(state, "PRIVMSG %s :Re-enabling default channel %s.\r\n",
                   nick, arg1);
        config_write(state, state->startup_password);
      }
      chan_t *c = channel_add(state, channel_name);

      if (c && arg2) {
        strncpy(c->key, arg2, MAX_KEY - 1);
      }
      config_write(state, state->startup_password);
      irc_printf(state, "PRIVMSG %s :JOIN %s and saving config file.\r\n", nick,
                 arg1);
    } else if (strcasecmp(command, "part") == 0 && arg1) {
      char channel_name[MAX_CHAN];
      if (arg1[0] == '#') {
        strncpy(channel_name, arg1, sizeof(channel_name) - 1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      if (strcasecmp(arg1, DEFAULT_CHANNEL) == 0) {
        strncpy(state->ignored_default_channel, arg1, MAX_CHAN - 1);
        irc_printf(
            state,
            "PRIVMSG %s :%s is a default channel and will now be ignored.\r\n",
            nick, arg1);
        config_write(state, state->startup_password);
      }

      if (channel_remove(state, arg1)) {
        irc_printf(state, "PART %s\r\n", channel_name);
        irc_printf(state, "PRIVMSG %s :PART %s.\r\n", nick, arg1);
        config_write(state, state->startup_password);
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

      irc_printf(state, "PRIVMSG %s :--- Bot Status ---\r\n", nick);
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
          const char *status_str =
              (current_chan->status == C_IN) ? "IN" : "OUT";
          if (current_chan->key[0] != '\0') {
            snprintf(chan_part, sizeof(chan_part), "%s (Key: %s) (%s)",
                     current_chan->name, current_chan->key, status_str);
          } else {
            snprintf(chan_part, sizeof(chan_part), "%s (%s)",
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
    } else if (strcasecmp(command, "setnick") == 0 && arg1) {
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
    } else if (strcasecmp(command, "setlog") == 0 && arg1) {
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
    } else if (strcasecmp(command, "+adminmask") == 0 && arg1) {
      if (state->mask_count < MAX_MASKS) {
        state->auth_masks[state->mask_count++] = strdup(arg1);
        state->auth_masks[state->mask_count] = NULL;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Added auth mask: %s\r\n", nick, arg1);
      } else {
        irc_printf(state,
                   "PRIVMSG %s :Error: Mask list is full. Please use "
                   "-adminmask to remove unused masks.\r\n",
                   nick);
      }
    } else if (strcasecmp(command, "-adminmask") == 0 && arg1) {
      if (strcasecmp(arg1, DEFAULT_USERMASK) == 0) {
        strncpy(state->ignored_default_mask, arg1, MAX_MASK_LEN - 1);
        config_write(state, state->startup_password);
        irc_printf(
            state,
            "PRIVMSG %s :Default user mask is now ignored and saved.\r\n",
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
        irc_printf(state, "PRIVMSG %s :Removed auth mask: %s\r\n", nick, arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Mask not found.\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "+opmask") == 0 && arg1 && arg2) {
      if (state->op_mask_count < MAX_OP_MASKS) {
        strncpy(state->op_masks[state->op_mask_count].mask, arg1,
                MAX_MASK_LEN - 1);
        strncpy(state->op_masks[state->op_mask_count].password, arg2,
                MAX_PASS - 1);
        state->op_mask_count++;
        config_write(state, state->startup_password);
        irc_printf(state, "PRIVMSG %s :Added op mask for %s.\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "-opmask") == 0 && arg1) {
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
    } else if (strcasecmp(command, "+server") == 0 && arg1) {
      if (strcasecmp(arg1, DEFAULT_SERVER) == 0) {
        state->default_server_ignored = false;
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Default server is now enabled and saved.\r\n",
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
    } else if (strcasecmp(command, "-server") == 0 && arg1) {
      if (strcasecmp(arg1, DEFAULT_SERVER) == 0) {
        state->default_server_ignored = true;
        config_write(state, state->startup_password);
        irc_printf(state,
                   "PRIVMSG %s :Default server is now ignored and saved.\r\n",
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
    } else if (strcasecmp(command, "help") == 0) {
      irc_printf(state,
                 "PRIVMSG %s :Admin commands: die, +server, -server, jump, op, "
                 "join, part, status, givenick, setnick, +adminmask, "
                 "-adminmask, saveconf, setlog, help\r\n",
                 nick);
    }
  } else if (auth_verify_op_command(state, user_host, password_attempt)) {
    log_message(L_CMD, state, "[CMD] Op command from %s: %s\n", user_host,
                command);
    if (strcasecmp(command, "op") == 0 && arg1) {
      irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
    }
  }
}
