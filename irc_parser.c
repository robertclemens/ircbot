#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

void parser_handle_line(bot_state_t *state, char *line) {
  if (strncmp(line, "PING :", 6) == 0) {
    irc_printf(state, "PONG :%s\r\n", line + 6);
    state->last_pong_time = time(NULL);
    state->pong_pending = false;
    return;
  }

  char line_copy[MAX_BUFFER];
  strncpy(line_copy, line, sizeof(line_copy) - 1);
  line_copy[sizeof(line_copy) - 1] = '\0';

  char *prefix = NULL, *command = NULL, *params = NULL;
  char *p = line_copy;

  if (*p == ':') {
    prefix = p + 1;
    p = strchr(p, ' ');
    if (!p) return;
    *p++ = '\0';
  }

  command = p;
  p = strchr(p, ' ');
  if (p) {
    *p++ = '\0';
    params = p;
  } else {
    return;
  }

  char *saveptr_irc;

  if (strcmp(command, "PONG") == 0) {
    state->last_pong_time = time(NULL);
    state->pong_pending = false;
    return;
  }
  if (strcmp(command, "004") == 0) {
    char *server_name = strtok_r(params, " ", &saveptr_irc);
    server_name = strtok_r(NULL, " ", &saveptr_irc);
    if (server_name) {
      strncpy(state->actual_server_name, server_name,
              sizeof(state->actual_server_name) - 1);
    }
  }
  if (strcmp(command, "001") == 0) {
    state->status |= S_AUTHED;
  } else if (strcmp(command, "433") == 0) {
    state->nick_change_pending = false;
    if (!(state->status & S_AUTHED)) {
      irc_generate_new_nick(state);
    }
  } else if (strcmp(command, "474") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
      }
    }
  } else if (strcmp(command, "MODE") == 0 && params) {
    char params_copy[MAX_BUFFER];
    strncpy(params_copy, params, sizeof(params_copy) - 1);
    params_copy[sizeof(params_copy) - 1] = '\0';

    char *target = strtok_r(params_copy, " ", &saveptr_irc);
    char *modes = strtok_r(NULL, " ", &saveptr_irc);

    if (!target || !modes) return;

    chan_t *c = channel_find(state, target);
    if (!c) return;

    char *mode_ptr = modes;
    bool adding = true;
    int nick_index = 0;

    char *nicks[MAX_ROSTER_SIZE];
    int nick_count = 0;
    char *nick;
    while ((nick = strtok_r(NULL, " ", &saveptr_irc)) != NULL && nick_count < MAX_ROSTER_SIZE) {
        nicks[nick_count++] = nick;
    }

    while (*mode_ptr) {
        if (*mode_ptr == '+') {
            adding = true;
        } else if (*mode_ptr == '-') {
            adding = false;
        } else if (*mode_ptr == 'o' && nick_index < nick_count) {
            char *affected_nick = nicks[nick_index++];

            if (strcasecmp(affected_nick, state->current_nick) == 0) {
                if (adding) {
                    log_message(L_INFO, state,
                                "[INFO] Received ops in %s. Clearing op request.\n",
                                target);
                    c->op_request_pending = false;

                    for (int i = 0; i < c->roster_count; i++) {
                        if (strcasecmp(c->roster[i].nick, state->current_nick) == 0) {
                            c->roster[i].is_op = true;
                            break;
                        }
                    }
                } else {
                    log_message(L_INFO, state, "[INFO] Lost ops in %s. Requesting help immediately.\n", target);

                    for (int i = 0; i < c->roster_count; i++) {
                        if (strcasecmp(c->roster[i].nick, state->current_nick) == 0) {
                            c->roster[i].is_op = false;
                            break;
                        }
                    }

                    bool found_helper = false;
                    if (!c->op_request_pending) {
                        roster_entry_t *helpers[MAX_ROSTER_SIZE];
                        int helper_count = 0;

                        for (int i = 0; i < c->roster_count; i++) {
                            roster_entry_t *entry = &c->roster[i];
                            if (entry->is_op && auth_is_trusted_bot(state, entry->hostmask)) {
                                if (helper_count < MAX_ROSTER_SIZE) {
                                    helpers[helper_count++] = entry;
                                }
                            }
                        }

                        if (helper_count > 0) {
                            int random_index = rand() % helper_count;
                            roster_entry_t *chosen_helper = helpers[random_index];

                            log_message(L_INFO, state,
                                        "[INFO] Found %d trusted ops in current roster. "
                                        "Requesting ops from: %s\n",
                                        helper_count, chosen_helper->nick);

                            bot_comms_send_command(state, chosen_helper->nick, "OPME %s", c->name);
                            c->op_request_pending = true;
                            found_helper = true;
                        }
                    }

                    if (!found_helper && !c->op_request_pending) {
                        log_message(L_DEBUG, state,
                                    "[DEBUG] No trusted ops in current roster. "
                                    "Refreshing roster for %s\n",
                                    c->name);
                        c->roster_count = 0;
                        irc_printf(state, "WHO %s\r\n", c->name);
                        c->last_who_request = time(NULL);
                    }
                }
            } else {
                for (int i = 0; i < c->roster_count; i++) {
                    if (strcasecmp(c->roster[i].nick, affected_nick) == 0) {
                        c->roster[i].is_op = adding;
                        log_message(L_DEBUG, state, "[DEBUG] Updated roster: %s is_op=%d in %s\n",
                                    affected_nick, adding, target);
                        break;
                    }
                }
            }
        } else if (*mode_ptr == 'v' || *mode_ptr == 'b' || *mode_ptr == 'k' ||
                   *mode_ptr == 'l' || *mode_ptr == 'e' || *mode_ptr == 'I') {
            nick_index++;
        }
        mode_ptr++;
    }
   } else if (strcmp(command, "352") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);

    chan_t *c = channel_find(state, chan_name);
    if (!c || c->roster_count >= MAX_ROSTER_SIZE) return;

    char *ident = strtok_r(NULL, " ", &saveptr_irc);
    char *host = strtok_r(NULL, " ", &saveptr_irc);
    strtok_r(NULL, " ", &saveptr_irc);
    char *nick = strtok_r(NULL, " ", &saveptr_irc);
    char *modes = strtok_r(NULL, " ", &saveptr_irc);

    if (nick && ident && host && modes) {
      roster_entry_t *entry = &c->roster[c->roster_count];
      strncpy(entry->nick, nick, MAX_NICK - 1);
      snprintf(entry->hostmask, MAX_MASK_LEN, "%s!%s@%s", nick, ident, host);
      entry->is_op = (strstr(modes, "@") != NULL);
      c->roster_count++;
    }
  } else if (strcmp(command, "315") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (!chan_name) return;

    chan_t *c = channel_find(state, chan_name);
    if (!c) return;

    log_message(L_INFO, state, "[INFO] Roster for %s updated with %d users.\n",
                c->name, c->roster_count);

    bool am_i_opped = false;
    for (int i = 0; i < c->roster_count; i++) {
        if (strcasecmp(c->roster[i].nick, state->current_nick) == 0 &&
            c->roster[i].is_op) {
            am_i_opped = true;
            break;
        }
    }

    if (am_i_opped) {
        if (c->op_request_pending) {
            log_message(L_INFO, state, "[INFO] We have ops in %s now. Clearing request.\n",
                        c->name);
            c->op_request_pending = false;
            c->op_request_retry_count = 0;
        }
        return;
    }

    time_t now = time(NULL);
    if (c->op_request_pending && (now - c->last_op_request_time < 60)) {
        log_message(L_DEBUG, state,
                    "[DEBUG] Op request already pending for %s (sent %ld seconds ago)\n",
                    c->name, now - c->last_op_request_time);
        return;
    }
    if (c->op_request_retry_count >= 5) {
        log_message(L_INFO, state,
                    "[INFO] Gave up requesting ops in %s after %d attempts.\n",
                    c->name, c->op_request_retry_count);
        return;
    }

    log_message(L_INFO, state,
                "[INFO] Not an operator in %s, searching for a trusted op...\n",
                c->name);

    roster_entry_t *helpers[MAX_ROSTER_SIZE];
    int helper_count = 0;

    for (int i = 0; i < c->roster_count; i++) {
        roster_entry_t *entry = &c->roster[i];
        if (entry->is_op && auth_is_trusted_bot(state, entry->hostmask)) {
            if (helper_count < MAX_ROSTER_SIZE) {
                helpers[helper_count++] = entry;
            }
        }
    }

    if (helper_count > 0) {
        int random_index = rand() % helper_count;
        roster_entry_t *chosen_helper = helpers[random_index];

        log_message(L_INFO, state,
                    "[INFO] Found %d trusted ops. Randomly selected: %s. "
                    "Sending OPME request (attempt %d).\n",
                    helper_count, chosen_helper->nick, c->op_request_retry_count + 1);

        bot_comms_send_command(state, chosen_helper->nick, "OPME %s", c->name);
        c->last_op_request_time = now;
        c->op_request_pending = true;
        c->op_request_retry_count++;
    } else {
        log_message(L_INFO, state, "[INFO] No trusted operators found in %s.\n",
                    c->name);
        c->last_op_request_time = now;
        c->op_request_retry_count++;
    }
  } else if (strcmp(command, "PRIVMSG") == 0 && prefix) {
    char *nick = strtok_r(prefix, "!", &saveptr_irc);
    char *user = strtok_r(NULL, "@", &saveptr_irc);
    char *host = strtok_r(NULL, "", &saveptr_irc);
    char *dest = strtok_r(params, " ", &saveptr_irc);
    char *message = strtok_r(NULL, "", &saveptr_irc);
    if (message && *message == ':') message++;

    if (nick && dest && message) {
      if (message[0] == '\001' && message[strlen(message) - 1] == '\001') {
        log_message(L_CTCP, state, "[CTCP] (%s) %s\n", nick, message);

        message[strlen(message) - 1] = '\0';
        char *ctcp_command = message + 1;

        if (strcasecmp(ctcp_command, "VERSION") == 0) {
          irc_printf(state, "NOTICE %s :\001VERSION %s\001\r\n", nick,
                     VERSION_RESPONSE);
        } else if (strncasecmp(ctcp_command, "PING ", 5) == 0) {
          irc_printf(state, "NOTICE %s :\001%s\001\r\n", nick, ctcp_command);
        }
      } else {
        commands_handle_private_message(state, nick, user, host, dest, message);
      }
    }
  } else if (strcmp(command, "JOIN") == 0 && prefix) {
    char *nick = strtok_r(prefix, "!", &saveptr_irc);
    if (nick && (strcasecmp(nick, state->current_nick) == 0 ||
                 strcasecmp(nick, state->target_nick) == 0)) {
      char *chan_name = (*params == ':') ? params + 1 : params;
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_IN;
        c->roster_count = 0;
        strncpy(state->who_request_channel, c->name, MAX_CHAN - 1);
        state->who_request_channel[MAX_CHAN - 1] = '\0';
        c->last_who_request = time(NULL);
        irc_printf(state, "WHO %s\r\n", c->name);
      }
    }
  } else if (strcmp(command, "KICK") == 0 && params) {
    char params_copy[MAX_BUFFER];
    strncpy(params_copy, params, sizeof(params_copy) - 1);
    params_copy[sizeof(params_copy) - 1] = '\0';

    char *chan_name = strtok_r(params_copy, " ", &saveptr_irc);
    char *kicked_nick = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name && kicked_nick &&
        strcasecmp(kicked_nick, state->current_nick) == 0) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
      }
    }
  } else if (strcmp(command, "NICK") == 0 && prefix) {
    char *old_nick = strtok_r(prefix, "!", &saveptr_irc);
    char *new_nick = (*params == ':') ? params + 1 : params;
    if (old_nick && new_nick &&
        strcasecmp(old_nick, state->current_nick) == 0) {
      strncpy(state->current_nick, new_nick, MAX_NICK - 1);
      state->nick_change_pending = false;
      if (strcasecmp(state->current_nick, state->target_nick) == 0) {
        state->nick_generation_attempt = 0;
      }
    }
  }
}
