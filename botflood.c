/* Bot floods, the ignore table and quiet mode (irchub docs/modes.md §9.1).
 *
 *   cmd   per user record: sealed ~A2/~A2S commands about to run, PRIVMSG and
 *         DCC together.  Over N in the window: drop, with one "slow down"
 *         notice per window.  Over 3N: the user is ignored for ignoretime.
 *   msg   per host: PRIVMSG / NOTICE to the bot that are not commands --
 *         failed or malformed ~A2..., ~A2A, plain text.  Over N: host ignored.
 *   ctcp  per host: CTCP to the bot.  Over N: host ignored (no replies).
 *
 * Limits come from the D| record (`bflood cmd|msg|ctcp`, `ignoretime`) or the
 * built-ins 10:30, 5:60, 3:60 and 10 minutes (chancfg_get_flood / chancfg_get).
 * Authorised sources (trusted bots, hosts matching an active usermask) are
 * never counted or ignored by host.  The ignore table holds MAX_IGNORES
 * entries and is never persisted or shared (D34).  When it is full and its
 * oldest entry is under a minute old -- many hosts at once, a botnet -- the
 * bot goes quiet for ignoretime: it answers no unauthorised source at all,
 * logged once per episode.  Windows are judged on arrival, no timers. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bot.h"

static bool host_key(const char *nuh, char *out, size_t out_size) {
  const char *bang = nuh ? strchr(nuh, '!') : NULL;
  const char *at = bang ? strchr(bang, '@') : NULL;
  if (!at || !at[1])
    return false;
  size_t n = 0;
  for (const char *p = at + 1; *p && n + 1 < out_size; p++, n++)
    out[n] = (char)tolower((unsigned char)*p);
  out[n] = '\0';
  return true;
}

static long long ignore_ms(const bot_state_t *state) {
  return (long long)chancfg_get(state, NULL, CS_IGNORETIME) * 60000LL;
}

/* A first managed channel we are in, to hang a console event on. */
static void emit_ignore(bot_state_t *state, const char *target,
                        const char *detail) {
  for (chan_t *c = state->chanlist; c; c = c->next) {
    if (c->is_managed && c->status == C_IN) {
      hub_client_chan_event(state, c->name, "ignore", target, detail);
      return;
    }
  }
}

static bool quiet_at(bot_state_t *state, long long now_ms) {
  if (state->quiet_until_ms && now_ms >= state->quiet_until_ms) {
    state->quiet_until_ms = 0;
    state->quiet_logged = false;
  }
  return state->quiet_until_ms != 0;
}

bool botflood_quiet(bot_state_t *state) {
  return quiet_at(state, flood_now_ms());
}

static const ignore_ent_t *ignore_find(const bot_state_t *state, const char *key,
                                       long long now_ms) {
  for (int i = 0; i < MAX_IGNORES; i++) {
    const ignore_ent_t *e = &state->ignores[i];
    if (e->key[0] && e->until_ms > now_ms && strcmp(e->key, key) == 0)
      return e;
  }
  return NULL;
}

/* Put `key` in the table.  False when it did not fit (quiet mode began). */
static bool ignore_add(bot_state_t *state, const char *key, long long now_ms) {
  ignore_ent_t *slot = NULL, *oldest = NULL;
  for (int i = 0; i < MAX_IGNORES; i++) {
    ignore_ent_t *e = &state->ignores[i];
    if (e->key[0] && e->until_ms <= now_ms)
      e->key[0] = '\0'; /* expired */
    if (e->key[0] && strcmp(e->key, key) == 0) {
      slot = e; /* already there: extend */
      break;
    }
    if (!e->key[0]) {
      if (!slot)
        slot = e;
    } else if (!oldest || e->since_ms < oldest->since_ms) {
      oldest = e;
    }
  }
  if (!slot) {
    if (oldest && now_ms - oldest->since_ms <= QUIET_FILL_MS) {
      state->quiet_until_ms = now_ms + ignore_ms(state);
      if (!state->quiet_logged) {
        state->quiet_logged = true;
        log_message(L_INFO, state,
                    "[FLOOD] Ignore table full within a minute: quiet mode for "
                    "%ld min, no replies to unauthorised sources\n",
                    (long)chancfg_get(state, NULL, CS_IGNORETIME));
      }
      return false;
    }
    slot = oldest; /* full, but the oldest has had its time: replace it */
  }
  if (!slot)
    return false;
  if (strcmp(slot->key, key) != 0) {
    snprintf(slot->key, sizeof(slot->key), "%s", key);
    slot->since_ms = now_ms;
  }
  slot->until_ms = now_ms + ignore_ms(state);
  return true;
}

static host_flood_t *host_slot(bot_state_t *state, const char *host,
                               long long now_ms) {
  host_flood_t *free_slot = NULL, *oldest = NULL;
  for (int i = 0; i < MAX_HOST_TRACK; i++) {
    host_flood_t *h = &state->host_flood[i];
    if (!h->host[0]) {
      if (!free_slot)
        free_slot = h;
    } else if (strcmp(h->host, host) == 0) {
      h->last_ms = now_ms;
      return h;
    } else if (!oldest || h->last_ms < oldest->last_ms) {
      oldest = h;
    }
  }
  host_flood_t *h = free_slot ? free_slot : oldest;
  memset(h, 0, sizeof(*h));
  snprintf(h->host, sizeof(h->host), "%s", host);
  h->last_ms = now_ms;
  return h;
}

/* Shared body of msg / ctcp. */
static int host_flood_at(bot_state_t *state, const char *nuh, bool authorised,
                         flood_kind_t kind, long long now_ms) {
  char host[FLOOD_HOST_MAX];
  if (authorised || !host_key(nuh, host, sizeof(host)))
    return BF_OK;
  if (quiet_at(state, now_ms) || ignore_find(state, host, now_ms))
    return BF_IGNORE;
  int n, s;
  if (!chancfg_get_flood(state, NULL, kind, &n, &s))
    return BF_OK; /* off */
  host_flood_t *h = host_slot(state, host, now_ms);
  flood_window_t *w = kind == FL_BOT_MSG ? &h->msg : &h->ctcp;
  if (!flood_window_hit(w, n, s, now_ms))
    return BF_OK;
  const char *what = kind == FL_BOT_MSG ? "msg" : "ctcp";
  log_message(L_INFO, state,
              "[FLOOD] %s flood (%d:%d) from %s: ignoring it for %ld min\n",
              what, n, s, host, (long)chancfg_get(state, NULL, CS_IGNORETIME));
  if (ignore_add(state, host, now_ms)) {
    char detail[96];
    snprintf(detail, sizeof(detail), "%s flood %d:%d, ignored %ld min", what, n,
             s, (long)chancfg_get(state, NULL, CS_IGNORETIME));
    emit_ignore(state, host, detail);
  }
  return BF_IGNORE;
}

int botflood_msg_at(bot_state_t *state, const char *nuh, bool authorised,
                    long long now_ms) {
  return host_flood_at(state, nuh, authorised, FL_BOT_MSG, now_ms);
}

int botflood_ctcp_at(bot_state_t *state, const char *nuh, bool authorised,
                     long long now_ms) {
  return host_flood_at(state, nuh, authorised, FL_BOT_CTCP, now_ms);
}

int botflood_msg(bot_state_t *state, const char *nuh) {
  return botflood_msg_at(state, nuh, auth_is_authorised(state, nuh),
                         flood_now_ms());
}

int botflood_ctcp(bot_state_t *state, const char *nuh) {
  return botflood_ctcp_at(state, nuh, auth_is_authorised(state, nuh),
                          flood_now_ms());
}

bool botflood_host_ignored(bot_state_t *state, const char *nuh) {
  char host[FLOOD_HOST_MAX];
  if (!host_key(nuh, host, sizeof(host)) || auth_is_authorised(state, nuh))
    return false;
  long long now = flood_now_ms();
  return quiet_at(state, now) || ignore_find(state, host, now) != NULL;
}

int botflood_cmd_at(bot_state_t *state, const user_record_t *who,
                    long long now_ms, bool *notice) {
  if (notice)
    *notice = false;
  if (!who || !who->uuid[0])
    return BF_OK;
  char key[IGNORE_KEY_MAX];
  snprintf(key, sizeof(key), "u:%s", who->uuid);
  if (ignore_find(state, key, now_ms))
    return BF_IGNORE;
  int n, s;
  if (!chancfg_get_flood(state, NULL, FL_BOT_CMD, &n, &s))
    return BF_OK;

  cmd_flood_t *slot = NULL, *free_slot = NULL, *oldest = NULL;
  for (int i = 0; i < MAX_USER_RECORDS; i++) {
    cmd_flood_t *f = &state->cmd_flood[i];
    if (!f->uuid[0]) {
      if (!free_slot)
        free_slot = f;
    } else if (strcmp(f->uuid, who->uuid) == 0) {
      slot = f;
      break;
    } else if (!oldest || f->last_ms < oldest->last_ms) {
      oldest = f;
    }
  }
  if (!slot) {
    slot = free_slot ? free_slot : oldest;
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->uuid, sizeof(slot->uuid), "%s", who->uuid);
  }
  slot->last_ms = now_ms;
  if (slot->w.count <= 0 || now_ms - slot->w.start_ms >= (long long)s * 1000) {
    slot->w.start_ms = now_ms;
    slot->w.count = 0;
    slot->notified = false;
  }
  slot->w.count++;
  if (slot->w.count > 3 * n) {
    log_message(L_INFO, state,
                "[FLOOD] WARNING: user %s is sending commands at over 3x the "
                "limit (%d:%d): ignored for %ld min\n", who->name, n, s,
                (long)chancfg_get(state, NULL, CS_IGNORETIME));
    ignore_add(state, key, now_ms);
    slot->w.count = 0;
    slot->notified = false;
    return BF_IGNORE_NEW;
  }
  if (slot->w.count > n) {
    if (notice && !slot->notified)
      *notice = true;
    slot->notified = true;
    return BF_DROP;
  }
  return BF_OK;
}

int botflood_cmd(bot_state_t *state, const user_record_t *who, const char *nick) {
  bool notice;
  int r = botflood_cmd_at(state, who, flood_now_ms(), &notice);
  if (r == BF_DROP && notice && nick)
    irc_printf(state, "PRIVMSG %s :Slow down: too many commands, some were "
                      "dropped.\r\n", nick);
  if (r == BF_IGNORE_NEW && who) {
    char detail[96];
    snprintf(detail, sizeof(detail), "command flood, ignored %ld min",
             (long)chancfg_get(state, NULL, CS_IGNORETIME));
    emit_ignore(state, who->name, detail);
  }
  return r;
}
