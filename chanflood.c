/* Channel floods (irchub docs/modes.md §8).
 *
 * Every opped or not bot counts the same channel events and so agrees when a
 * flood trips; only the holder of the matching election job acts (the
 * chanenf_request_* hooks queue the work in the §7 deal), and a bot that is
 * not opped only logs.  There are no timers: a window is opened by the first
 * event from a source and judged when the next one arrives, so more than N
 * events within S seconds of the window's start trip it (N+1, not N).  After
 * a trip the window starts afresh, so one burst is one trip.
 *
 * Sources are keyed by host (a nick change does not reset a window).  The
 * tracker holds MAX_FLOOD_TRACK sources per channel; when it is full the
 * source idle longest is replaced.  Authorised members, this bot and server
 * sources are never counted; with +dontkickops neither are ops for the
 * chan / ctcp / join / nick floods.  A halfop's kicks and bans count in the
 * op floods (D41). */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bot.h"

long long flood_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool flood_window_hit(flood_window_t *w, int n, int s, long long now_ms) {
  if (w->count <= 0 || now_ms - w->start_ms >= (long long)s * 1000) {
    w->start_ms = now_ms;
    w->count = 0;
  }
  w->count++;
  if (w->count > n) {
    w->start_ms = 0;
    w->count = 0;
    return true;
  }
  return false;
}

/* Lower-cased host of nick!user@host; false when there is no '!' and '@'
 * (a server source) or the host is empty. */
static bool src_host(const char *nuh, char *out, size_t out_size) {
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

static bool src_nick(const char *nuh, char *out, size_t out_size) {
  const char *bang = nuh ? strchr(nuh, '!') : NULL;
  if (!bang || bang == nuh || (size_t)(bang - nuh) >= out_size)
    return false;
  memcpy(out, nuh, (size_t)(bang - nuh));
  out[bang - nuh] = '\0';
  return true;
}

static const roster_entry_t *roster_by_nick(const chan_t *c, const char *nick) {
  for (int i = 0; i < c->roster_count; i++)
    if (strcasecmp(c->roster[i].nick, nick) == 0)
      return &c->roster[i];
  return NULL;
}

bool chanflood_count_at(bot_state_t *state, chan_t *c, const char *nuh,
                        flood_kind_t kind, bool victim_auth, long long now_ms,
                        bool *auth_victim_out) {
  if (auth_victim_out)
    *auth_victim_out = false;
  if (!c || (int)kind < 0 || kind >= FL_CHAN_COUNT)
    return false;
  int n, s;
  if (!chancfg_get_flood(state, c, kind, &n, &s))
    return false; /* off */
  char host[FLOOD_HOST_MAX], nick[MAX_MEMBER_NICK];
  if (!src_host(nuh, host, sizeof(host)) || !src_nick(nuh, nick, sizeof(nick)))
    return false;
  if (chanenf_chan_nuh_authorised(state, c, nuh))
    return false;
  bool text_kind = kind == FL_CHAN || kind == FL_CTCP || kind == FL_JOIN ||
                   kind == FL_NICK;
  if (text_kind && chancfg_get(state, c, CS_DONTKICKOPS)) {
    const roster_entry_t *e = roster_by_nick(c, nick);
    if (e && e->is_op)
      return false;
  }

  if (!c->flood) {
    c->flood = calloc(MAX_FLOOD_TRACK, sizeof(*c->flood));
    if (!c->flood)
      return false;
  }
  flood_src_t *slot = NULL, *freeslot = NULL, *oldest = NULL;
  for (int i = 0; i < MAX_FLOOD_TRACK; i++) {
    flood_src_t *f = &c->flood[i];
    if (!f->host[0]) {
      if (!freeslot)
        freeslot = f;
    } else if (strcmp(f->host, host) == 0) {
      slot = f;
      break;
    } else if (!oldest || f->last_ms < oldest->last_ms) {
      oldest = f;
    }
  }
  if (!slot) {
    slot = freeslot ? freeslot : oldest; /* full: the longest idle goes */
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->host, sizeof(slot->host), "%s", host);
  }
  slot->last_ms = now_ms;
  if (victim_auth)
    slot->victim_auth |= (uint8_t)(1u << kind);
  if (!flood_window_hit(&slot->w[kind], n, s, now_ms))
    return false;
  if (auth_victim_out)
    *auth_victim_out = (slot->victim_auth & (1u << kind)) != 0;
  slot->victim_auth &= (uint8_t)~(1u << kind);
  return true;
}

static const char *const KIND_NAME[FL_CHAN_COUNT] = {
  "chan", "ctcp", "join", "nick", "deop", "kick", "ban",
};

/* §8.3: what a trip does. */
static void trip(bot_state_t *state, chan_t *c, const char *nuh,
                 flood_kind_t kind, bool auth_victim) {
  char nick[MAX_MEMBER_NICK];
  if (!src_nick(nuh, nick, sizeof(nick)))
    return;
  int n = 0, s = 0;
  chancfg_get_flood(state, c, kind, &n, &s);
  unsigned off = chanenf_offence(state, c->name, nuh);
  bool op_flood = kind == FL_DEOP || kind == FL_KICK || kind == FL_BAN;
  bool ban_step;
  if (kind == FL_JOIN)
    ban_step = true; /* a join flood is returning: ban + kick at once */
  else if (op_flood)
    ban_step = off >= 2 || (chancfg_get(state, c, CS_REVENGE) && auth_victim);
  else
    ban_step = off >= 2;
  int job = ban_step ? JOB_BAN : (op_flood ? JOB_OP : JOB_KICK);
  const char *act = ban_step ? "kick+ban" : (op_flood ? "deop" : "kick");
  char reason[BAN_REASON_MAX + 1];
  snprintf(reason, sizeof(reason), "%s flood", KIND_NAME[kind]);

  int rank = chanenf_deal_rank(state, c, job);
  log_message(L_INFO, state,
              "[FLOOD] %s flood (%d:%d) in %s by %s, offence %u -> %s%s\n",
              KIND_NAME[kind], n, s, c->name, nuh, off, act,
              rank < 0 ? " (not opped or not in the deal: logged only)" : "");
  bool queued;
  if (ban_step)
    queued = chanenf_request_ban(state, c->name, nuh, reason, true);
  else if (op_flood)
    queued = chanenf_request_deop(state, c->name, nick, reason);
  else
    queued = chanenf_request_kick(state, c->name, nick, reason);
  /* One chan event per trip: from the bot that holds the job. */
  if (queued && rank == 0) {
    char detail[160];
    snprintf(detail, sizeof(detail), "%s flood %d:%d, offence %u: %s",
             KIND_NAME[kind], n, s, off, act);
    hub_client_chan_event(state, c->name, "floodtrip", nick, detail);
  }
}

void chanflood_event(bot_state_t *state, const char *chan, const char *nuh,
                     flood_kind_t kind, bool victim_auth) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || c->status != C_IN || !nuh)
    return;
  bool auth_victim;
  if (chanflood_count_at(state, c, nuh, kind, victim_auth, flood_now_ms(),
                         &auth_victim))
    trip(state, c, nuh, kind, auth_victim);
}

/* Text sent to a channel (PRIVMSG or NOTICE): CTCP other than ACTION counts
 * as ctcp, everything else as chan. */
void chanflood_on_text(bot_state_t *state, const char *chan, const char *nick,
                       const char *user, const char *host, const char *msg) {
  if (!chan || !nick || !user || !host || !msg)
    return;
  char nuh[MAX_MASK_LEN];
  if (snprintf(nuh, sizeof(nuh), "%s!%s@%s", nick, user, host) >=
      (int)sizeof(nuh))
    return;
  bool ctcp = msg[0] == '\001' && strncasecmp(msg + 1, "ACTION", 6) != 0;
  chanflood_event(state, chan, nuh, ctcp ? FL_CTCP : FL_CHAN, false);
}
