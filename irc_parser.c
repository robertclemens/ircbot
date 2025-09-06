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

  if (strcmp(command, "PONG") == 0) {
    state->last_pong_time = time(NULL);
    state->pong_pending = false;
    return;
  }
  if (strcmp(command, "004") == 0) {
    char *server_name = strtok(params, " ");
    server_name = strtok(NULL, " ");
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
    strtok(params, " ");
    char *chan_name = strtok(NULL, " ");
    if (chan_name) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
      }
    }
  } else if (strcmp(command, "PRIVMSG") == 0 && prefix) {
    char *nick = strtok(prefix, "!");
    char *user = strtok(NULL, "@");
    char *host = strtok(NULL, "");
    char *dest = strtok(params, " ");
    char *message = strtok(NULL, "");
    if (message && *message == ':') message++;
    if (nick && dest && message) {
      commands_handle_private_message(state, nick, user, host, dest, message);
    }
  } else if (strcmp(command, "JOIN") == 0 && prefix) {
    char *nick = strtok(prefix, "!");
    if (nick && (strcasecmp(nick, state->current_nick) == 0 ||
                 strcasecmp(nick, state->target_nick) == 0)) {
      char *chan_name = (*params == ':') ? params + 1 : params;
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_IN;
      }
    }
  } else if (strcmp(command, "KICK") == 0 && params) {
    char params_copy[MAX_BUFFER];
    strncpy(params_copy, params, sizeof(params_copy) - 1);
    params_copy[sizeof(params_copy) - 1] = '\0';

    char *chan_name = strtok(params_copy, " ");
    char *kicked_nick = strtok(NULL, " ");
    if (chan_name && kicked_nick &&
        strcasecmp(kicked_nick, state->current_nick) == 0) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
      }
    }
  } else if (strcmp(command, "NICK") == 0 && prefix) {
    char *old_nick = strtok(prefix, "!");
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
