#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

chan_t *channel_add(bot_state_t *state, const char *name) {
  if (channel_find(state, name)) {
    return NULL;
  }
  chan_t *new_chan = calloc(1, sizeof(chan_t));
  if (!new_chan) handle_fatal_error("calloc failed");

  strncpy(new_chan->name, name, MAX_CHAN - 1);
  new_chan->status = C_OUT;
  new_chan->last_join_attempt = 0;

  new_chan->key[0] = '\0';

  new_chan->next = NULL;

  if (state->chanlist == NULL) {
    state->chanlist = new_chan;
  } else {
    chan_t *current = state->chanlist;
    while (current->next != NULL) {
      current = current->next;
    }
    current->next = new_chan;
  }

  return new_chan;
}

bool channel_remove(bot_state_t *state, const char *name) {
  chan_t *current = state->chanlist, *prev = NULL;
  while (current) {
    if (strcasecmp(current->name, name) == 0) {
      if (prev)
        prev->next = current->next;
      else
        state->chanlist = current->next;
      free(current);
      return true;
    }
    prev = current;
    current = current->next;
  }
  return false;
}

chan_t *channel_find(const bot_state_t *state, const char *name) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (strcasecmp(c->name, name) == 0) return c;
  }
  return NULL;
}

void channel_list_destroy(bot_state_t *state) {
  chan_t *current = state->chanlist;
  while (current) {
    chan_t *next = current->next;
    free(current);
    current = next;
  }
  state->chanlist = NULL;
}

void channel_list_reset_status(bot_state_t *state) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    c->status = C_OUT;
    c->last_join_attempt = 0;
  }
}

void channel_manager_check_joins(bot_state_t *state) {
  if (!(state->status & S_AUTHED)) return;
  time_t now = time(NULL);

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (c->status != C_IN && (now - c->last_join_attempt > JOIN_RETRY_TIME)) {
      if (c->key[0] != '\0') {
        log_message(L_INFO, state, "[INFO] JOIN with key %s\n", c->name);
        irc_printf(state, "JOIN %s %s\r\n", c->name, c->key);
      } else {
        log_message(L_INFO, state, "[INFO] JOIN without key %s\n", c->name);
        irc_printf(state, "JOIN %s\r\n", c->name);
      }
      c->last_join_attempt = now;
    }
  }
}
