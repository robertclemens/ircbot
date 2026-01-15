#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

// [UPDATED] Helper to handle mode changes securely + immediate Op Recovery
static void channel_handle_mode_change(bot_state_t *state, const char *channel, 
                                       const char *modes, char *args) {
    chan_t *c = channel_find(state, channel);
    if (!c) return;

    bool adding = true; // Default direction
    char *saveptr;
    // Initialize tokenizing the arguments string
    char *current_arg = strtok_r(args, " ", &saveptr);

    for (int i = 0; modes[i] != '\0'; i++) {
        char mode = modes[i];

        if (mode == '+') {
            adding = true;
        } else if (mode == '-') {
            adding = false;
        } 
        // --- Modes that ALWAYS take an argument ---
        else if (mode == 'o' || mode == 'v' || mode == 'b' || mode == 'e' || mode == 'I') {
            if (current_arg) {
                // Handle OPS (+o / -o)
                if (mode == 'o') {
                    // Check if it affects US
                    if (strcasecmp(current_arg, state->current_nick) == 0) {
                        for(int k=0; k < c->roster_count; k++) {
                            if(strcasecmp(c->roster[k].nick, state->current_nick) == 0) {
                                c->roster[k].is_op = adding;
                                break;
                            }
                        }
                        if (adding) {
                            c->op_request_pending = false; 
                            log_message(L_INFO, state, "[INFO] I am now OP in %s\n", channel);
                        } else {
                            // [RESTORED] Immediate Op Recovery Logic
                            log_message(L_INFO, state, "[INFO] I was DEOPPED in %s. Requesting help immediately.\n", channel);
                            
                            bool found_helper = false;
                            
                            // Only request if we aren't already pending (to prevent spam loops)
                            if (!c->op_request_pending) {
                                roster_entry_t *helpers[MAX_ROSTER_SIZE];
                                int helper_count = 0;

                                // 1. Scan existing roster for trusted bots that are OPs
                                for (int x = 0; x < c->roster_count; x++) {
                                    roster_entry_t *entry = &c->roster[x];
                                    if (entry->is_op && auth_is_trusted_bot(state, entry->hostmask)) {
                                        if (helper_count < MAX_ROSTER_SIZE) {
                                            helpers[helper_count++] = entry;
                                        }
                                    }
                                }

                                // 2. Pick one and request ops
                                if (helper_count > 0) {
                                    int random_index = rand() % helper_count;
                                    roster_entry_t *chosen_helper = helpers[random_index];

                                    log_message(L_INFO, state,
                                                "[INFO] Found %d trusted ops. Requesting ops from: %s\n",
                                                helper_count, chosen_helper->nick);

                                    bot_comms_send_command(state, chosen_helper->nick, "OPME %s", c->name);
                                    c->op_request_pending = true;
                                    c->last_op_request_time = time(NULL);
                                    found_helper = true;
                                }
                            }

                            // 3. If no helper found, trigger immediate roster refresh
                            if (!found_helper && !c->op_request_pending) {
                                log_message(L_DEBUG, state,
                                            "[DEBUG] No trusted ops found locally. Refreshing roster for %s\n",
                                            c->name);
                                c->roster_count = 0;
                                irc_printf(state, "WHO %s\r\n", c->name);
                                c->last_who_request = time(NULL);
                            }
                        }
                    } 
                    // Check if it affects SOMEONE ELSE in our roster
                    else {
                        for(int k=0; k < c->roster_count; k++) {
                            if(strcasecmp(c->roster[k].nick, current_arg) == 0) {
                                c->roster[k].is_op = adding;
                                log_message(L_DEBUG, state, "[DEBUG] Roster update: %s is_op=%d in %s\n", 
                                            current_arg, adding, channel);
                                break;
                            }
                        }
                    }
                }
                
                // Consumed one argument, move to next
                current_arg = strtok_r(NULL, " ", &saveptr);
            }
        }
        // --- Modes that CONDITIONALLY take an argument ---
        else if (mode == 'k') {
            if (current_arg) current_arg = strtok_r(NULL, " ", &saveptr);
        }
        else if (mode == 'l') {
            // +l takes arg (limit). -l DOES NOT take arg.
            if (adding && current_arg) {
                current_arg = strtok_r(NULL, " ", &saveptr);
            }
        }
        // --- Modes that NEVER take an argument (t, s, i, n, m, p, etc) ---
    }
}

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
  } 
  // [MODIFIED] Robust MODE Parsing + Immediate Op Recovery
  else if (strcmp(command, "MODE") == 0 && params) {
      char params_copy[MAX_BUFFER];
      strncpy(params_copy, params, sizeof(params_copy) - 1);
      params_copy[sizeof(params_copy) - 1] = '\0';

      char *target = strtok_r(params_copy, " ", &saveptr_irc);
      char *modes = strtok_r(NULL, " ", &saveptr_irc);
      char *args = strtok_r(NULL, "", &saveptr_irc);
      
      if (target && modes && (target[0] == '#' || target[0] == '&')) {
          channel_handle_mode_change(state, target, modes, args);
      }
  } 
  else if (strcmp(command, "352") == 0) {
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
        return;
    }
    if (c->op_request_retry_count >= 5) {
        log_message(L_INFO, state,
                    "[INFO] Gave up requesting ops in %s after %d attempts.\n",
                    c->name, c->op_request_retry_count);
        return;
    }

    // Standard Polling Logic (runs if roster refresh happened naturally)
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
