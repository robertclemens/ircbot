#include "bot.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>


chan_t *channel_add(bot_state_t *state, const char *name) {
  if (channel_find(state, name)) {
    return NULL;
  }
  chan_t *new_chan = calloc(1, sizeof(chan_t));
  if (!new_chan)
    handle_fatal_error("calloc failed");

  strncpy(new_chan->name, name, MAX_CHAN - 1);
  new_chan->status = C_OUT;
  new_chan->last_join_attempt = 0;
  new_chan->key[0] = '\0';
  new_chan->roster_count = 0;
  new_chan->op_request_pending = false;
  new_chan->last_op_request_time = 0;
  new_chan->op_request_retry_count = 0;
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
  state->chan_count++;
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
      state->chan_count--;
      return true;
    }
    prev = current;
    current = current->next;
  }
  return false;
}

chan_t *channel_find(const bot_state_t *state, const char *name) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (strcasecmp(c->name, name) == 0)
      return c;
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
  state->chan_count = 0;
}

void channel_list_reset_status(bot_state_t *state) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    c->status = C_OUT;
    c->last_join_attempt = 0;
    c->op_request_pending = false;
    c->op_request_retry_count = 0;
  }
}

void channel_manager_check_joins(bot_state_t *state) {
  if (!(state->status & S_AUTHED))
    return;

  time_t now = time(NULL);

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    // Skip tombstoned/deleted channels
    if (!c->is_managed)
      continue;

    if (c->status != C_IN && (now - c->last_join_attempt > JOIN_RETRY_TIME)) {
      if (c->key[0] != '\0') {
        irc_printf(state, "JOIN %s %s\r\n", c->name, c->key);
      } else {
        irc_printf(state, "JOIN %s\r\n", c->name);
      }
      c->last_join_attempt = now;
      continue;
    }
    if (c->status == C_IN) {
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
          log_message(L_DEBUG, state,
                      "[DEBUG] We have ops in %s. Clearing pending request.\n",
                      c->name);
          c->op_request_pending = false;
          c->op_request_retry_count = 0;
        }
        continue;
      }
      bool should_refresh = false;
      if (c->roster_count == 0 && (now - c->last_who_request > 30)) {
        log_message(L_DEBUG, state,
                    "[DEBUG] No roster for %s. Requesting WHO.\n", c->name);
        should_refresh = true;
      } else if (now - c->last_who_request > ROSTER_REFRESH_INTERVAL) {
        log_message(L_DEBUG, state,
                    "[DEBUG] Periodic roster refresh for %s (not opped).\n",
                    c->name);
        should_refresh = true;
      } else if (c->op_request_pending &&
                 (now - c->last_op_request_time > 60) &&
                 c->op_request_retry_count < 5) {
        log_message(L_DEBUG, state,
                    "[DEBUG] Op request timeout in %s. Refreshing to retry.\n",
                    c->name);
        should_refresh = true;
        c->op_request_pending = false;
      }
      if (should_refresh) {
        c->roster_count = 0;
        irc_printf(state, "WHO %s\r\n", c->name);
        c->last_who_request = now;
      }
    }
  }
}
