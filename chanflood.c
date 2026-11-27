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
    if (irc_casecmp(c->roster[i].nick, nick) == 0)
      return &c->roster[i];
  return NULL;
}

/* A bot was just added to (or updated in) the trusted list: its joins seen
 * before the hub told us who it is were counted as a stranger's.  Forget the
 * join windows of its host in every channel, so a newly linked bot's own
 * autojoin never trips join flood against the next stranger from that host
 * (every bot of one host joining at once), and lift any automatic ban this
 * bot already placed on it (a join flood's own grace, JOIN_FLOOD_GRACE_MS,
 * normally drops the kick+ban before it is sent). */
/* "nick!user" of nick!user@host into out; false without '!' and '@'. */
static bool src_nu(const char *nuh, char *out, size_t out_size) {
  const char *bang = strchr(nuh, '!'), *at = bang ? strchr(bang, '@') : NULL;
  size_t n = at ? (size_t)(at - nuh) : 0;
  if (!at || n == 0 || n >= out_size)
    return false;
  memcpy(out, nuh, n);
  out[n] = '\0';
  return true;
}

/* A trusted bot's mask became known: take its own joins off its host's join
 * window, and only those.  Every other user on that host keeps their count
 * (flood windows are per host, so clones cannot hop nicks).  A bot whose
 * joins were not recorded (the table was full) is subtracted nothing: its own
 * early join stays counted, which the 5 s grace and the exact-mask ban lift
 * still cover. */
void chanflood_trusted(bot_state_t *state, const char *mask) {
  char host[FLOOD_HOST_MAX], nu[MAX_MASK_LEN];
  if (!src_host(mask, host, sizeof(host)) || !src_nu(mask, nu, sizeof(nu)))
    return;
  for (chan_t *c = state->chanlist; c; c = c->next) {
    if (!c->flood)
      continue;
    for (int i = 0; i < MAX_FLOOD_TRACK; i++) {
      flood_src_t *f = &c->flood[i];
      if (!f->host[0] || strcmp(f->host, host) != 0)
        continue;
      for (int k = 0; k < FLOOD_JOIN_CONTRIB; k++) {
        flood_contrib_t *j = &f->jc[k];
        if (!j->nu[0] || irc_casecmp(j->nu, nu) != 0)
          continue;
        flood_window_t *w = &f->w[FL_JOIN];
        w->count -= j->count;
        if (w->count <= 0)
          *w = (flood_window_t){0, 0};
        memset(j, 0, sizeof(*j));
      }
    }
  }
  chanenf_trusted_lift(state, mask);
}

/* Note nuh's join in its host slot's open window (FLOOD_JOIN_CONTRIB: a new
 * contributor past the table is not recorded). */
static void join_contrib(flood_src_t *slot, const char *nuh) {
  char nu[MAX_MASK_LEN];
  if (!src_nu(nuh, nu, sizeof(nu)))
    return;
  flood_contrib_t *free_j = NULL;
  for (int k = 0; k < FLOOD_JOIN_CONTRIB; k++) {
    flood_contrib_t *j = &slot->jc[k];
    if (j->nu[0] && irc_casecmp(j->nu, nu) == 0) {
      j->count++;
      return;
    }
    if (!j->nu[0] && !free_j)
      free_j = j;
  }
  if (free_j) {
    snprintf(free_j->nu, sizeof(free_j->nu), "%s", nu);
    free_j->count = 1;
  }
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
  if (kind == FL_JOIN) {
    /* the window restarts on this event: its contributors go with it */
    const flood_window_t *w = &slot->w[FL_JOIN];
    if (w->count <= 0 || now_ms - w->start_ms >= (long long)s * 1000)
      memset(slot->jc, 0, sizeof(slot->jc));
  }
  if (!flood_window_hit(&slot->w[kind], n, s, now_ms)) {
    if (kind == FL_JOIN)
      join_contrib(slot, nuh);
    return false;
  }
  if (kind == FL_JOIN)
    memset(slot->jc, 0, sizeof(slot->jc)); /* tripped: the window is closed */
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
  char join_act[48];
  snprintf(join_act, sizeof(join_act), "kick+ban unless trusted within %d s",
           JOIN_FLOOD_GRACE_MS / 1000);
  const char *act = kind == FL_JOIN ? join_act
                    : ban_step ? "kick+ban" : (op_flood ? "deop" : "kick");
  char reason[BAN_REASON_MAX + 1];
  snprintf(reason, sizeof(reason), "%s flood", KIND_NAME[kind]);

  int rank = chanenf_deal_rank(state, c, job);
  log_message(L_INFO, state,
              "[FLOOD] %s flood (%d:%d) in %s by %s, offence %u -> %s%s\n",
              KIND_NAME[kind], n, s, c->name, nuh, off, act,
              rank < 0 ? " (not opped or not in the deal: logged only)" : "");
  bool queued;
  if (ban_step)
    queued = chanenf_request_ban(state, c->name, nuh, reason, true,
                                 kind == FL_JOIN ? JOIN_FLOOD_GRACE_MS : 0);
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
