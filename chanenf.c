/* In-channel elections and set-option enforcement (irchub docs/modes.md §4,
 * §6, §7).
 *
 * Nobody tells the bots who acts.  Every opped trusted bot in a channel sees
 * the same member list, so each computes the same deal (chanenf_deal_rank):
 * the five jobs (kick, ban, op, mode, limit) are dealt over those bots in
 * SHA-256(lower(chan) || uuid) order, job j to position j mod n, backups
 * following.  A bot that is the job's holder acts at once; a backup queues
 * the work and acts after backup-index x JOB_STEP_MS if it is still needed.
 * Whoever acts, the action is re-checked against the current roster / live
 * modes / ban list first, so a duplicate costs at most a MODE the server
 * ignores.
 *
 * Two kinds of trigger feed the jobs: events (a MODE with a source, a KICK,
 * a JOIN -- needed where *who did it* matters: protectops, revenge,
 * stopnethack, bitch on a receiver) and the state sweep (chanenf_tick, per
 * channel on the dirty flag and every ENF_SWEEP_SECS: enforcemodes, the ban
 * list, dynamic limit, cycle).  All MODE / KICK lines leave through
 * irc_printf, i.e. the paced queue's protection lane.  Every action goes
 * through the act_* primitives: opped, target unauthorised (or, for a
 * re-op, authorised), event to the hub (D42).
 *
 * The roster is kept current here from JOIN / PART / QUIT / KICK / NICK, so
 * an opped bot (which no longer polls WHO) still sees who is there. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/evp.h>

#include "bot.h"

#define RECENT_ACT_MS  30000   /* same kick / deop / reop again: pending until
                                * its MODE / KICK echo (recent_ack) or this */
#define RECENT_BAN_MS  30000
#define RECENT_MODE_MS 10000   /* mode revert / limit change */

static long long now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return (long long)time(NULL) * 1000;
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* --- small helpers -------------------------------------------------------- */

static bool valid_nick(const bot_state_t *state, const char *n) {
  size_t len = n ? strlen(n) : 0;
  if (len == 0 || len > (size_t)isupport_nicklen(state))
    return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)n[i];
    if (!(isalnum(ch) || strchr("[]\\`_^{|}-", ch)))
      return false;
  }
  return true;
}

/* A token we may put on an IRC line: no space, no control byte. */
static bool safe_token(const char *s, size_t max) {
  size_t len = s ? strlen(s) : 0;
  if (len == 0 || len > max)
    return false;
  for (size_t i = 0; i < len; i++)
    if ((unsigned char)s[i] <= 0x20 || s[i] == 0x7f)
      return false;
  return true;
}

static void lower_copy(char *dst, size_t dsz, const char *src) {
  size_t i = 0;
  for (; src[i] && i + 1 < dsz; i++)
    dst[i] = (char)tolower((unsigned char)src[i]);
  dst[i] = '\0';
}

/* nick part of a "nick!user@host" (or bare nick) into out. */
static bool nuh_nick(const char *nuh, char *out, size_t out_size) {
  if (!nuh)
    return false;
  const char *bang = strchr(nuh, '!');
  size_t n = bang ? (size_t)(bang - nuh) : strlen(nuh);
  if (n == 0 || n >= out_size)
    return false;
  memcpy(out, nuh, n);
  out[n] = '\0';
  return true;
}

static bool is_me(const bot_state_t *state, const char *nick) {
  return nick && strcasecmp(nick, state->current_nick) == 0;
}

static int rindex_of(const chan_t *c, const char *nick) {
  for (int i = 0; i < c->roster_count; i++)
    if (strcasecmp(c->roster[i].nick, nick) == 0)
      return i;
  return -1;
}

static roster_entry_t *rfind(chan_t *c, const char *nick) {
  int i = rindex_of(c, nick);
  return i < 0 ? NULL : &c->roster[i];
}

static void rremove(chan_t *c, const char *nick) {
  for (int i = 0; i < c->roster_count; i++) {
    if (strcasecmp(c->roster[i].nick, nick) == 0) {
      memmove(&c->roster[i], &c->roster[i + 1],
              (size_t)(c->roster_count - i - 1) * sizeof(c->roster[0]));
      c->roster_count--;
      return;
    }
  }
}

bool chanenf_nuh_authorised(const bot_state_t *state, const char *nuh) {
  char nick[MAX_MEMBER_NICK];
  if (!nuh || !nuh_nick(nuh, nick, sizeof(nick)))
    return false;
  if (is_me(state, nick))
    return true;
  return auth_is_authorised(state, nuh);
}

/* What "authorised" depends on: the trusted bots, the user and mask records
 * (none of which has one change hook) and cfg_gen.  The records are hashed
 * at most every 200 ms; a change bumps state->auth_gen, which retires every
 * roster entry's cached verdict at once. */
static uint64_t fp_str(uint64_t h, const char *s) {
  for (; *s; s++)
    h = (h ^ (unsigned char)*s) * UINT64_C(1099511628211);
  return (h ^ 0xff) * UINT64_C(1099511628211);
}

static unsigned auth_epoch(bot_state_t *state) {
  long long ms = now_ms();
  if (state->auth_gen && state->auth_seen_cfg_gen == state->cfg_gen &&
      ms - state->auth_fp_ms < 200)
    return state->auth_gen;
  uint64_t h = 14695981039346656037ULL;
  for (int i = 0; i < state->trusted_bot_count; i++) {
    h = fp_str(h, state->trusted_bots[i].mask);
    h = fp_str(h, state->trusted_bots[i].uuid);
  }
  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *m = &state->mask_records[i];
    h = fp_str(fp_str(h, m->mask), m->uuid) + (uint64_t)m->is_active;
  }
  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *u = &state->user_records[i];
    h = fp_str(h, u->uuid) + (uint64_t)u->is_active;
  }
  h = h * UINT64_C(1099511628211) + (uint64_t)state->trusted_bot_count * 3 +
      (uint64_t)state->mask_record_count * 5 + (uint64_t)state->user_record_count;
  if (!state->auth_gen || h != state->auth_fp ||
      state->auth_seen_cfg_gen != state->cfg_gen) {
    state->auth_fp = h;
    state->auth_seen_cfg_gen = state->cfg_gen;
    if (++state->auth_gen == 0)
      state->auth_gen = 1;
  }
  state->auth_fp_ms = ms;
  return state->auth_gen;
}

/* The roster lives in state->channels, which is never const: a caller's const
 * view still names a writable entry, so writing its cache fields is defined.
 * The union drops the qualifier without a cast. */
static roster_entry_t *roster_cache(const roster_entry_t *e) {
  union { const roster_entry_t *ro; roster_entry_t *rw; } u = { .ro = e };
  return u.rw;
}

/* The verdict is cached in the entry (only its cache fields change, so the
 * const is dropped by roster_cache); every wildcard match against the bots /
 * masks is paid once per entry per auth_gen instead of once per ban x entry. */
static bool entry_authorised(bot_state_t *state, const roster_entry_t *e) {
  if (is_me(state, e->nick))
    return true;
  roster_entry_t *m = roster_cache(e);
  unsigned gen = auth_epoch(state);
  if (m->auth_gen != gen) {
    m->authorised = auth_is_authorised(state, m->hostmask);
    m->auth_gen = gen;
  }
  return m->authorised;
}

bool chanenf_chan_nuh_authorised(bot_state_t *state, const chan_t *c,
                                 const char *nuh) {
  char nick[MAX_MEMBER_NICK];
  if (!nuh || !nuh_nick(nuh, nick, sizeof(nick)))
    return false;
  if (is_me(state, nick))
    return true;
  int ri = c ? rindex_of(c, nick) : -1;
  const roster_entry_t *e = ri < 0 ? NULL : &c->roster[ri];
  if (e && strcasecmp(e->hostmask, nuh) == 0)
    return entry_authorised(state, e);
  return auth_is_authorised(state, nuh);
}

bool chanenf_roster_set(chan_t *c, const char *nick, const char *hostmask,
                        bool op, bool halfop, bool voice) {
  if (!nick || !hostmask || strlen(nick) >= MAX_MEMBER_NICK ||
      strlen(hostmask) >= MAX_MASK_LEN)
    return false;
  roster_entry_t *e = rfind(c, nick);
  if (!e) {
    if (c->roster_count >= MAX_ROSTER_SIZE)
      return false;
    e = &c->roster[c->roster_count++];
  }
  snprintf(e->nick, sizeof(e->nick), "%s", nick);
  snprintf(e->hostmask, sizeof(e->hostmask), "%s", hostmask);
  e->auth_gen = 0; /* the cached verdict was for the old hostmask */
  e->is_op = op;
  e->is_halfop = halfop;
  e->is_voice = voice;
  return true;
}

static bool live_has_ban(const chan_t *c, const char *mask) {
  for (int i = 0; i < c->ban_count; i++)
    if (strcasecmp(c->bans[i].mask, mask) == 0)
      return true;
  return false;
}

bool chanenf_key_managed(const bot_state_t *state, const chan_t *c) {
  if (!chancfg_get(state, c, CS_ENFORCEMODES))
    return false;
  const char *m = chancfg_get_modes(state, c);
  for (; *m && *m != ' '; m++)
    if (*m == 'k')
      return true;
  return false;
}

/* --- the deal (§7.1) ------------------------------------------------------ */

typedef struct {
  uint64_t h;
  char     id[64];
} elig_t;

static bool bot_too_old(const bot_state_t *state, const char *id) {
  for (int i = 0; i < state->bot_tree_count; i++) {
    const bot_tree_row_t *r = &state->bot_tree[i];
    if (r->kind == 'h' || strcmp(r->uuid, id) != 0)
      continue;
    /* version unknown (empty) = keep it in the deal */
    if (r->version[0] && updater_version_cmp(r->version, JOB_MIN_VERSION) < 0)
      return true;
  }
  return false;
}

static bool elig_add(elig_t *el, int *n, const char *lc_chan, const char *id) {
  for (int i = 0; i < *n; i++)
    if (strcmp(el[i].id, id) == 0)
      return false;
  unsigned char buf[MAX_CHAN + 64], md[EVP_MAX_MD_SIZE];
  unsigned int mdl = 0;
  size_t cl = strlen(lc_chan), il = strlen(id);
  if (cl + il > sizeof(buf))
    return false;
  memcpy(buf, lc_chan, cl);
  memcpy(buf + cl, id, il);
  if (EVP_Digest(buf, cl + il, md, &mdl, EVP_sha256(), NULL) != 1 || mdl < 8)
    return false;
  uint64_t h = 0;
  for (int i = 0; i < 8; i++)
    h = (h << 8) | md[i];
  el[*n].h = h;
  snprintf(el[*n].id, sizeof(el[*n].id), "%s", id);
  (*n)++;
  return true;
}

static int elig_cmp(const elig_t *a, const elig_t *b) {
  if (a->h != b->h)
    return a->h < b->h ? -1 : 1;
  return strcmp(a->id, b->id);
}

int chanenf_deal_rank(bot_state_t *state, const chan_t *c, int job) {
  if (!c || !c->i_am_opped || job < 0 || job >= JOB_COUNT)
    return -1;
  elig_t el[MAX_ROSTER_SIZE + 1];
  int n = 0;
  char lc[MAX_CHAN], me[64];
  lower_copy(lc, sizeof(lc), c->name);
  snprintf(me, sizeof(me), "%s",
           state->bot_uuid[0] ? state->bot_uuid : state->current_nick);
  if (!elig_add(el, &n, lc, me))
    return -1;
  for (int i = 0; i < c->roster_count && n < MAX_ROSTER_SIZE + 1; i++) {
    const roster_entry_t *e = &c->roster[i];
    if (!e->is_op || is_me(state, e->nick))
      continue;
    trusted_bot_t *tb = auth_trusted_bot_by_host(state, e->hostmask);
    if (!tb)
      continue;
    const char *id = tb->uuid[0] ? tb->uuid : tb->mask;
    if (bot_too_old(state, id))
      continue;
    elig_add(el, &n, lc, id);
  }
  /* sort: n is tiny */
  for (int i = 1; i < n; i++) {
    elig_t t = el[i];
    int j = i - 1;
    while (j >= 0 && elig_cmp(&el[j], &t) > 0) {
      el[j + 1] = el[j];
      j--;
    }
    el[j + 1] = t;
  }
  int pos = -1;
  for (int i = 0; i < n; i++)
    if (strcmp(el[i].id, me) == 0)
      pos = i;
  if (pos < 0)
    return -1;
  int primary = job % n;
  return (pos - primary + n) % n;
}

/* --- ban masks (§6.1) ----------------------------------------------------- */

static bool all_in(const char *s, size_t len, const char *set) {
  for (size_t i = 0; i < len; i++)
    if (!strchr(set, s[i]))
      return false;
  return len > 0;
}

/* The host widened one step; cloaks and short names stay as they are. */
static void widen_host(const char *host, char *out, size_t out_size) {
  size_t hl = strlen(host);
  snprintf(out, out_size, "%s", host);
  if (strchr(host, '/'))
    return; /* cloak: never widened */
  if (strchr(host, ':')) {
    /* IPv6: the /64 = the first four groups, when they are spelled out. */
    if (!all_in(host, hl, "0123456789abcdefABCDEF:."))
      return;
    int colons = 0;
    for (size_t i = 0; i < hl; i++) {
      if (host[i] == ':') {
        colons++;
        if (colons < 4 && i + 1 < hl && host[i + 1] == ':')
          return; /* "::" inside the first four groups: cannot cut by text */
        if (colons == 4) {
          if (i + 2 > out_size - 1 || i + 2 > hl + 2)
            return;
          memcpy(out, host, i + 1);
          out[i + 1] = '*';
          out[i + 2] = '\0';
          return;
        }
      }
    }
    return;
  }
  if (all_in(host, hl, "0123456789.")) {
    /* IPv4 a.b.c.d -> a.b.c.* */
    int dots = 0;
    size_t last = 0, seg = 0;
    for (size_t i = 0; i < hl; i++) {
      if (host[i] == '.') {
        if (seg == 0 || seg > 3)
          return;
        dots++;
        last = i;
        seg = 0;
      } else {
        seg++;
      }
    }
    if (dots != 3 || seg == 0 || seg > 3 || last + 2 > out_size - 1)
      return;
    memcpy(out, host, last + 1);
    out[last + 1] = '*';
    out[last + 2] = '\0';
    return;
  }
  /* name: 3 or more labels -> *.<all but the first> */
  int labels = 1;
  for (size_t i = 0; i < hl; i++) {
    if (host[i] == '.') {
      if (i == 0 || i + 1 == hl || host[i + 1] == '.')
        return; /* empty label: leave it */
      labels++;
    }
  }
  if (labels < 3)
    return;
  const char *dot = strchr(host, '.');
  snprintf(out, out_size, "*%s", dot);
}

bool chanenf_ban_mask(int type, const char *nuh, char *out, size_t out_size) {
  if (type < 0 || type > 9 || !nuh || !out || out_size == 0)
    return false;
  out[0] = '\0';
  const char *bang = strchr(nuh, '!');
  const char *at = bang ? strchr(bang, '@') : NULL;
  if (!bang || !at || at < bang + 2)
    return false;
  char nick[MAX_MEMBER_NICK], user[64], host[MAX_MASK_LEN];
  size_t nl = (size_t)(bang - nuh), ul = (size_t)(at - bang - 1);
  size_t hl = strlen(at + 1);
  if (nl == 0 || nl >= sizeof(nick) || ul == 0 || ul >= sizeof(user) ||
      hl == 0 || hl >= sizeof(host))
    return false;
  memcpy(nick, nuh, nl);
  nick[nl] = '\0';
  memcpy(user, bang + 1, ul);
  user[ul] = '\0';
  memcpy(host, at + 1, hl + 1);
  /* components are literal text: no wildcard, separator or control byte */
  const char *parts[3] = {nick, user, host};
  for (int p = 0; p < 3; p++) {
    if (!safe_token(parts[p], MAX_MASK_LEN))
      return false;
    if (strpbrk(parts[p], "*?!@,"))
      return false;
  }
  char whost[MAX_MASK_LEN];
  bool widen = (type == 3 || type == 4 || type == 8 || type == 9);
  if (widen)
    widen_host(host, whost, sizeof(whost));
  const char *h = widen ? whost : host;

  const char *nk = (type >= 5) ? nick : "*";
  char ubuf[80];
  switch (type % 5) {
  case 0:
    snprintf(ubuf, sizeof(ubuf), "%s", user);
    break;
  case 1: case 3:
    snprintf(ubuf, sizeof(ubuf), "*%s", user[0] == '~' ? user + 1 : user);
    break;
  default: /* 2, 4 */
    snprintf(ubuf, sizeof(ubuf), "*");
    break;
  }
  int n = snprintf(out, out_size, "%s!%s@%s", nk, ubuf, h);
  if (n < 0 || (size_t)n >= out_size || (size_t)n > BAN_MASK_MAX) {
    out[0] = '\0';
    return false;
  }
  return true;
}

/* §6.2 step 1+2 for a ban that has not been set yet.  The overlap half is a
 * glob DP against every bot / usermask, so the caller may pass a cached
 * overlap verdict. */
static bool allowed_members(bot_state_t *state, const chan_t *c,
                            const char *mask, char *who, size_t who_size) {
  if (who && who_size)
    who[0] = '\0';
  if (!c)
    return true;
  for (int i = 0; i < c->roster_count; i++) {
    const roster_entry_t *e = &c->roster[i];
    if (entry_authorised(state, e) && auth_wildcard_match(mask, e->hostmask)) {
      if (who && who_size)
        snprintf(who, who_size, "member %s", e->nick);
      return false;
    }
  }
  return true;
}

bool chanenf_ban_allowed(bot_state_t *state, const chan_t *c, const char *mask,
                         char *who, size_t who_size) {
  if (!mask || !safe_token(mask, BAN_MASK_MAX)) {
    if (who && who_size)
      snprintf(who, who_size, "bad mask");
    return false;
  }
  if (!allowed_members(state, c, mask, who, who_size))
    return false;
  return !auth_mask_overlaps_authorised(state, mask, who, who_size);
}

bool chanenf_auto_ban_mask(bot_state_t *state, const chan_t *c, const char *nuh,
                           char *out, size_t out_size) {
  int first = (int)chancfg_get(state, c, CS_BANTYPE);
  /* the configured type, then the narrowing retry 2 -> 0 -> 7 -> 5 */
  int order[5] = {first, 2, 0, 7, 5};
  for (int i = 0; i < 5; i++) {
    bool dup = false;
    for (int j = 0; j < i; j++)
      if (order[j] == order[i])
        dup = true;
    if (dup)
      continue;
    if (chanenf_ban_mask(order[i], nuh, out, out_size) &&
        chanenf_ban_allowed(state, c, out, NULL, 0))
      return true;
  }
  if (out_size)
    out[0] = '\0';
  return false;
}

/* --- per-ban runtime clocks ---------------------------------------------- */

/* The table is on the heap and grows to MAX_BAN_TRACK, enough for every
 * channel's bans and every global ban in every channel, so no clock is evicted
 * (and no banidle clock restarted) in practice.  A growth moves the table:
 * a caller reads what it needs from the result before the next track_get /
 * act_ban. */
static ban_track_t *track_get(bot_state_t *state, const char *chan,
                              const char *mask, time_t now) {
  ban_track_t *free_slot = NULL, *oldest = NULL;
  for (int i = 0; i < state->ban_track_count; i++) {
    ban_track_t *t = &state->ban_track[i];
    if (!t->chan[0]) {
      if (!free_slot)
        free_slot = t;
      continue;
    }
    if (strcasecmp(t->chan, chan) == 0 && strcasecmp(t->mask, mask) == 0)
      return t;
    if (!oldest || t->last_match < oldest->last_match)
      oldest = t;
  }
  ban_track_t *t = free_slot;
  if (!t && state->ban_track_count < MAX_BAN_TRACK) {
    if (state->ban_track_count == state->ban_track_cap) {
      int cap = state->ban_track_cap ? state->ban_track_cap * 2 : 64;
      if (cap > MAX_BAN_TRACK)
        cap = MAX_BAN_TRACK;
      ban_track_t *nt = realloc(state->ban_track, (size_t)cap * sizeof(*nt));
      if (nt) {
        state->ban_track = nt;
        state->ban_track_cap = cap;
      }
    }
    if (state->ban_track_count < state->ban_track_cap)
      t = &state->ban_track[state->ban_track_count++];
  }
  if (!t)
    t = oldest ? oldest : &state->ban_track[0]; /* full (or no memory) */
  memset(t, 0, sizeof(*t));
  snprintf(t->chan, sizeof(t->chan), "%s", chan);
  snprintf(t->mask, sizeof(t->mask), "%s", mask);
  t->last_match = now; /* the idle clock starts the first time we see it */
  return t;
}

unsigned chanenf_offence(bot_state_t *state, const char *chan, const char *nuh) {
  if (!chan || !nuh)
    return 1;
  const char *at = strchr(nuh, '@');
  char lc[MAX_CHAN], lh[120];
  lower_copy(lc, sizeof(lc), chan);
  lower_copy(lh, sizeof(lh), at ? at + 1 : nuh);
  char key[MAX_CHAN + 128];
  snprintf(key, sizeof(key), "%s|%s", lc, lh);
  chan_t *c = channel_find(state, chan);
  long bt = chancfg_get(state, c, CS_BANTIME);
  time_t now = time(NULL), span = bt > 0 ? (time_t)bt * 60 : 86400;
  offence_t *slot = NULL, *oldest = &state->offences[0];
  for (int i = 0; i < MAX_OFFENCES; i++) {
    offence_t *o = &state->offences[i];
    if (o->key[0] && now - o->when >= span)
      o->key[0] = '\0'; /* forgotten */
    if (o->key[0] && strcmp(o->key, key) == 0) {
      o->count++;
      o->when = now;
      return o->count;
    }
    if (!o->key[0]) {
      if (!slot)
        slot = o;
    } else if (o->when < oldest->when) {
      oldest = o;
    }
  }
  if (!slot)
    slot = oldest;
  snprintf(slot->key, sizeof(slot->key), "%s", key);
  slot->when = now;
  slot->count = 1;
  return 1;
}

/* --- action primitives ---------------------------------------------------- */

/* Same key again inside window_ms: skip (an echo has not arrived yet).
 * record false only looks. */
static bool recent_check(bot_state_t *state, const char *key,
                         long long window_ms, bool record) {
  long long t = now_ms();
  char lk[sizeof(state->enf_recent[0].key)];
  lower_copy(lk, sizeof(lk), key);
  for (int i = 0; i < ENF_RECENT; i++) {
    enf_recent_t *r = &state->enf_recent[i];
    if (r->when_ms && strcmp(r->key, lk) == 0 && t - r->when_ms < window_ms)
      return true;
  }
  if (!record)
    return false;
  enf_recent_t *r = &state->enf_recent[state->enf_recent_idx];
  state->enf_recent_idx = (state->enf_recent_idx + 1) % ENF_RECENT;
  snprintf(r->key, sizeof(r->key), "%s", lk);
  r->when_ms = t;
  return false;
}

static bool recent_key(bot_state_t *state, const chan_t *c, const char *act,
                       const char *target, long long window_ms) {
  char key[sizeof(state->enf_recent[0].key)];
  snprintf(key, sizeof(key), "%s|%s|%s", c->name, act, target);
  return recent_check(state, key, window_ms, true);
}

static bool recent_peek(bot_state_t *state, const chan_t *c, const char *act,
                        const char *target, long long window_ms) {
  char key[sizeof(state->enf_recent[0].key)];
  snprintf(key, sizeof(key), "%s|%s|%s", c->name, act, target);
  return recent_check(state, key, window_ms, false);
}

/* The echo of an act (our KICK / MODE coming back) ends its pending window. */
static void recent_ack(bot_state_t *state, const chan_t *c, const char *act,
                       const char *target) {
  char key[sizeof(state->enf_recent[0].key)], lk[sizeof(key)];
  snprintf(key, sizeof(key), "%s|%s|%s", c->name, act, target);
  lower_copy(lk, sizeof(lk), key);
  for (int i = 0; i < ENF_RECENT; i++)
    if (state->enf_recent[i].when_ms && strcmp(state->enf_recent[i].key, lk) == 0)
      state->enf_recent[i].when_ms = 0;
}

static void clean_reason(char *dst, size_t dsz, const char *src) {
  size_t k = 0;
  for (; src && *src && k + 1 < dsz; src++)
    dst[k++] = ((unsigned char)*src < 0x20 || *src == 0x7f) ? ' ' : *src;
  dst[k] = '\0';
}

static void act_deop(bot_state_t *state, chan_t *c, const char *nick,
                     const char *why, bool half) {
  if (!c->i_am_opped || !valid_nick(state, nick))
    return;
  roster_entry_t *e = rfind(c, nick);
  if (!e || (half ? !e->is_halfop : !e->is_op) || entry_authorised(state, e))
    return;
  char nk[MAX_MEMBER_NICK]; /* irc_printf can drop the link: no use of e after */
  snprintf(nk, sizeof(nk), "%s", e->nick);
  if (recent_key(state, c, half ? "dehalf" : "deop", nk, RECENT_ACT_MS))
    return;
  irc_printf(state, "MODE %s -%c %s\r\n", c->name, half ? 'h' : 'o', nk);
  hub_client_chan_event(state, c->name, "deop", nk, why);
}

static void act_reop(bot_state_t *state, chan_t *c, const char *nick,
                     const char *why) {
  if (!c->i_am_opped || !valid_nick(state, nick))
    return;
  roster_entry_t *e = rfind(c, nick);
  if (!e || e->is_op || is_me(state, e->nick) || !entry_authorised(state, e))
    return;
  char nk[MAX_MEMBER_NICK];
  snprintf(nk, sizeof(nk), "%s", e->nick);
  if (recent_key(state, c, "reop", nk, RECENT_ACT_MS))
    return;
  irc_printf(state, "MODE %s +o %s\r\n", c->name, nk);
  hub_client_chan_event(state, c->name, "reop", nk, why);
}

static void act_kick(bot_state_t *state, chan_t *c, const char *nick,
                     const char *reason) {
  if (!c->i_am_opped || !valid_nick(state, nick))
    return;
  roster_entry_t *e = rfind(c, nick);
  if (!e || entry_authorised(state, e))
    return;
  char nk[MAX_MEMBER_NICK];
  snprintf(nk, sizeof(nk), "%s", e->nick);
  if (recent_key(state, c, "kick", nk, RECENT_ACT_MS))
    return;
  char why[BAN_REASON_MAX + 1];
  clean_reason(why, sizeof(why), reason && reason[0] ? reason : "kicked");
  irc_printf(state, "KICK %s %s :%s\r\n", c->name, nk, why);
  hub_client_chan_event(state, c->name, "kick", nk, why);
}

static void act_ban(bot_state_t *state, chan_t *c, const char *mask_in,
                    const char *why) {
  if (!c->i_am_opped || !safe_token(mask_in, BAN_MASK_MAX))
    return;
  /* mask_in may point into c->bans or the job table: own copy, as the link
   * (and with it the ban list) can go away inside irc_printf */
  char mask[BAN_MASK_MAX + 1];
  snprintf(mask, sizeof(mask), "%s", mask_in);
  if (live_has_ban(c, mask))
    return;
  if (c->ban_list_known && c->ban_count >= isupport_ban_cap(state))
    return; /* the server's list is full */
  time_t now = time(NULL);
  ban_track_t *t = track_get(state, c->name, mask, now);
  if (now - t->set_at < RECENT_BAN_MS / 1000)
    return;
  /* §6.2: step 1 every time (who is in the channel), step 2 cached 60 s */
  char who[80];
  if (!allowed_members(state, c, mask, who, sizeof(who))) {
    log_message(L_INFO, state, "[BAN] Not setting %s in %s: it would hit %s\n",
                mask, c->name, who);
    return;
  }
  if (now - t->checked_at >= 60) {
    t->overlap_ok = !auth_mask_overlaps_authorised(state, mask, who, sizeof(who));
    t->checked_at = now;
    if (!t->overlap_ok)
      log_message(L_INFO, state, "[BAN] Not setting %s in %s: it overlaps %s\n",
                  mask, c->name, who);
  }
  if (!t->overlap_ok)
    return;
  t->set_at = now;
  irc_printf(state, "MODE %s +b %s\r\n", c->name, mask);
  hub_client_chan_event(state, c->name, "ban", mask, why);
}

static void act_unban(bot_state_t *state, chan_t *c, const char *mask_in,
                      const char *why) {
  if (!c->i_am_opped || !safe_token(mask_in, BAN_MASK_MAX))
    return;
  char mask[BAN_MASK_MAX + 1]; /* see act_ban */
  snprintf(mask, sizeof(mask), "%s", mask_in);
  if (!live_has_ban(c, mask))
    return;
  if (recent_key(state, c, "unban", mask, RECENT_ACT_MS))
    return;
  irc_printf(state, "MODE %s -b %s\r\n", c->name, mask);
  hub_client_chan_event(state, c->name, "unban", mask, why);
}

/* --- jobs ------------------------------------------------------------------ */

static int act_job(job_act_t a) {
  switch (a) {
  case JA_DEOP: case JA_DEHALF: case JA_REOP: return JOB_OP;
  case JA_KICK: return JOB_KICK;
  case JA_BAN_NUH: case JA_BAN_MASK: case JA_UNBAN: return JOB_BAN;
  case JA_MODE: return JOB_MODE;
  default: return JOB_LIMIT;
  }
}

static void exec_ban_nuh(bot_state_t *state, chan_t *c, const char *nuh,
                         const char *reason) {
  char nick[MAX_MEMBER_NICK];
  if (!nuh_nick(nuh, nick, sizeof(nick)) || !c->i_am_opped)
    return;
  roster_entry_t *e = rfind(c, nick);
  if ((e && entry_authorised(state, e)) ||
      chanenf_chan_nuh_authorised(state, c, nuh))
    return;
  char mask[BAN_MASK_MAX + 1];
  if (!chanenf_auto_ban_mask(state, c, nuh, mask, sizeof(mask))) {
    log_message(L_INFO, state,
                "[BAN] No ban type is safe for %s in %s; kick only\n", nuh,
                c->name);
    return;
  }
  long bt = chancfg_get(state, c, CS_BANTIME);
  if (bt > 0) {
    /* the record is how every bot (and a later joiner) learns of the ban and
     * who lifts it; the hub takes bot-written bans only when timed */
    chancfg_bot_ban(state, c->name, mask, time(NULL) + (time_t)bt * 60, "",
                    reason, false);
  }
  act_ban(state, c, mask, reason && reason[0] ? reason : "auto ban");
}

static void exec_mode(bot_state_t *state, chan_t *c) {
  if (!chancfg_get(state, c, CS_ENFORCEMODES) || !c->live_known || !c->i_am_opped)
    return;
  bool skip_limit = chancfg_get(state, c, CS_DYNAMICLIMIT) != 0;
  char sum[64];
  int n = chanmode_sync(state, c, skip_limit, true, true, sum, sizeof(sum));
  if (n <= 0 || recent_key(state, c, "moderevert", "", RECENT_MODE_MS))
    return;
  n = chanmode_sync(state, c, skip_limit, false, true, sum, sizeof(sum));
  if (n > 0)
    hub_client_chan_event(state, c->name, "moderevert", c->name, sum);
}

/* The +l the dynamic limit wants now, or 0 when the live one is close enough
 * (or cannot be judged).  The sweep queues the limit job only on a nonzero
 * answer, so a backup's delay counts from when it saw the need. */
static long limit_due(bot_state_t *state, chan_t *c) {
  /* the count is only right once the whole WHO has been read */
  if (!chancfg_get(state, c, CS_DYNAMICLIMIT) || !c->i_am_opped ||
      !c->who_done || c->roster_count >= MAX_ROSTER_SIZE || /* cannot count a big channel */
      !c->live_known)
    return 0;
  long want = c->roster_count + chancfg_get(state, c, CS_LIMITGAP);
  if (want < 1)
    want = 1;
  if (want > 99999)
    want = 99999;
  if (chan_live_has(c, 'l') && labs(c->live_limit - want) < 2)
    return 0; /* off by less than 2: no MODE every time someone joins */
  return want;
}

static void exec_limit(bot_state_t *state, chan_t *c) {
  long want = limit_due(state, c);
  /* a queued backup runs here too: it obeys limitdelay like the sweep */
  if (!want || time(NULL) - c->enf_last_limit < chancfg_get(state, c, CS_LIMITDELAY) ||
      recent_key(state, c, "limit", "", RECENT_MODE_MS))
    return;
  char det[32];
  snprintf(det, sizeof(det), "+l %ld", want);
  irc_printf(state, "MODE %s +l %ld\r\n", c->name, want);
  hub_client_chan_event(state, c->name, "limit", c->name, det);
}

static void job_exec(bot_state_t *state, chan_t *c, job_act_t act,
                     const char *target, const char *reason) {
  switch (act) {
  case JA_DEOP:     act_deop(state, c, target, reason, false); break;
  case JA_DEHALF:   act_deop(state, c, target, reason, true); break;
  case JA_REOP:     act_reop(state, c, target, reason); break;
  case JA_KICK:     act_kick(state, c, target, reason); break;
  case JA_BAN_NUH:  exec_ban_nuh(state, c, target, reason); break;
  case JA_BAN_MASK: act_ban(state, c, target, reason); break;
  case JA_UNBAN:    act_unban(state, c, target, reason); break;
  case JA_MODE:     exec_mode(state, c); break;
  case JA_LIMIT:    exec_limit(state, c); break;
  default: break;
  }
}

/* Hand a piece of work to the election: run it now when this bot holds the
 * job, otherwise queue it for backup-index x JOB_STEP_MS.  false = this bot
 * takes no part (not opped / not in the deal) or the queue is full. */
static bool job_submit(bot_state_t *state, chan_t *c, job_act_t act,
                       const char *target, const char *reason) {
  int rank = chanenf_deal_rank(state, c, act_job(act));
  if (rank < 0)
    return false;
  if (rank == 0) {
    job_exec(state, c, act, target, reason);
    return true;
  }
  pending_job_t *slot = NULL;
  for (int i = 0; i < MAX_PENDING_JOBS; i++) {
    pending_job_t *j = &state->jobs[i];
    if (!j->used) {
      if (!slot)
        slot = j;
      continue;
    }
    if (j->act == act && strcasecmp(j->chan, c->name) == 0 &&
        strcasecmp(j->target, target) == 0)
      return true; /* already waiting */
  }
  if (!slot) {
    log_message(L_DEBUG, state, "[JOB] Pending queue full; dropping a job in %s\n",
                c->name);
    return false;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = true;
  slot->act = (uint8_t)act;
  snprintf(slot->chan, sizeof(slot->chan), "%s", c->name);
  snprintf(slot->target, sizeof(slot->target), "%s", target);
  snprintf(slot->reason, sizeof(slot->reason), "%s", reason ? reason : "");
  slot->created_ms = now_ms();
  return true;
}

/* Forget this channel's queued (backup) work of one kind. */
static void jobs_drop(bot_state_t *state, const chan_t *c, job_act_t act) {
  for (int i = 0; i < MAX_PENDING_JOBS; i++) {
    pending_job_t *j = &state->jobs[i];
    if (j->used && j->act == act && strcasecmp(j->chan, c->name) == 0)
      j->used = false;
  }
}

static void jobs_tick(bot_state_t *state) {
  long long t = now_ms();
  for (int i = 0; i < MAX_PENDING_JOBS; i++) {
    pending_job_t *j = &state->jobs[i];
    if (!j->used)
      continue;
    chan_t *c = channel_find(state, j->chan);
    if (!c || c->status != C_IN || t - j->created_ms > JOB_MAX_AGE_MS) {
      j->used = false;
      continue;
    }
    /* re-dealt every tick: a roster change moves the rank */
    int rank = chanenf_deal_rank(state, c, act_job((job_act_t)j->act));
    if (rank < 0) {
      j->used = false;
      continue;
    }
    /* the limit job comes from each bot's own sweep, up to a sweep apart:
     * its backups give the holder one whole sweep first */
    long long wait = (long long)rank * JOB_STEP_MS;
    if (j->act == JA_LIMIT)
      wait += (long long)ENF_SWEEP_SECS * 1000;
    if (t - j->created_ms < wait)
      continue;
    pending_job_t copy = *j;
    j->used = false;
    /* queued under +bitch, which may be gone by now: a member given +o/+h
     * again after -bitch keeps it */
    if (strcmp(copy.reason, "bitch") == 0 && !chancfg_get(state, c, CS_BITCH))
      continue;
    job_exec(state, c, (job_act_t)copy.act, copy.target, copy.reason);
  }
}

/* --- hooks for the flood lane --------------------------------------------- */

bool chanenf_request_kick(bot_state_t *state, const char *chan, const char *nick,
                          const char *reason) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || c->status != C_IN || !valid_nick(state, nick))
    return false;
  return job_submit(state, c, JA_KICK, nick, reason);
}

bool chanenf_request_deop(bot_state_t *state, const char *chan, const char *nick,
                          const char *reason) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || c->status != C_IN || !valid_nick(state, nick))
    return false;
  return job_submit(state, c, JA_DEOP, nick, reason);
}

bool chanenf_request_ban(bot_state_t *state, const char *chan, const char *nuh,
                         const char *reason, bool kick_too) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  char nick[MAX_MEMBER_NICK];
  if (!c || c->status != C_IN || !nuh || strlen(nuh) >= MAX_MASK_LEN ||
      !nuh_nick(nuh, nick, sizeof(nick)) || !valid_nick(state, nick))
    return false;
  bool ok = job_submit(state, c, JA_BAN_NUH, nuh, reason);
  if (kick_too)
    job_submit(state, c, JA_KICK, nick, reason);
  return ok;
}

/* +revenge: the unauthorised `prefix` hurt an authorised member.  First time
 * within bantime: deop; again: kick + ban. */
static void revenge(bot_state_t *state, chan_t *c, const char *prefix) {
  char nick[MAX_MEMBER_NICK];
  if (!nuh_nick(prefix, nick, sizeof(nick)))
    return;
  if (chanenf_offence(state, c->name, prefix) <= 1)
    job_submit(state, c, JA_DEOP, nick, "revenge");
  else
    chanenf_request_ban(state, c->name, prefix, "revenge", true);
}

/* --- roster events --------------------------------------------------------- */

void chanenf_on_join(bot_state_t *state, const char *chan, const char *nuh) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  char nick[MAX_MEMBER_NICK];
  if (!c || c->status != C_IN || !nuh_nick(nuh, nick, sizeof(nick)) ||
      !strchr(nuh, '@') || is_me(state, nick))
    return;
  chanenf_roster_set(c, nick, nuh, false, false, false);
  c->enf_dirty = true;
  chanflood_event(state, c->name, nuh, FL_JOIN, false);
}

void chanenf_on_part(bot_state_t *state, const char *chan, const char *nick) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || !nick || is_me(state, nick))
    return;
  rremove(c, nick);
  c->enf_dirty = true;
}

void chanenf_on_quit(bot_state_t *state, const char *nick) {
  if (!nick || is_me(state, nick))
    return;
  for (chan_t *c = state->chanlist; c; c = c->next) {
    if (c->status == C_IN && rfind(c, nick)) {
      rremove(c, nick);
      c->enf_dirty = true;
    }
  }
}

void chanenf_on_kick(bot_state_t *state, const char *chan, const char *prefix,
                     const char *victim) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || c->status != C_IN || !victim || is_me(state, victim))
    return;
  roster_entry_t *e = rfind(c, victim);
  bool victim_auth = e && entry_authorised(state, e);
  recent_ack(state, c, "kick", victim);
  rremove(c, victim);
  c->enf_dirty = true;
  if (prefix && strchr(prefix, '!'))
    chanflood_event(state, c->name, prefix, FL_KICK, victim_auth);
  if (victim_auth && prefix && strchr(prefix, '!') &&
      chancfg_get(state, c, CS_REVENGE) && !chanenf_chan_nuh_authorised(state, c, prefix))
    revenge(state, c, prefix);
}

void chanenf_on_nick(bot_state_t *state, const char *old_nick,
                     const char *new_nick) {
  if (!old_nick)
    return;
  bool new_ok = valid_nick(state, new_nick);
  for (chan_t *c = state->chanlist; c; c = c->next) {
    roster_entry_t *e = (c->status == C_IN) ? rfind(c, old_nick) : NULL;
    if (!e)
      continue;
    if (!new_ok) {
      /* a nick we cannot track: forget the member rather than keep the old
       * name, which no longer exists */
      rremove(c, old_nick);
      c->enf_dirty = true;
      continue;
    }
    const char *bang = strchr(e->hostmask, '!');
    char mask[MAX_MASK_LEN];
    if (bang && snprintf(mask, sizeof(mask), "%s%s", new_nick, bang) <
                    (int)sizeof(mask)) {
      /* a stale entry under the new name -- but a case-only change (Bob ->
       * bob) names the same entry, which is renamed in place */
      if (strcasecmp(old_nick, new_nick) != 0)
        rremove(c, new_nick);
      e = rfind(c, old_nick);
      if (e) {
        snprintf(e->nick, sizeof(e->nick), "%s", new_nick);
        snprintf(e->hostmask, sizeof(e->hostmask), "%s", mask);
        e->auth_gen = 0;
        chanflood_event(state, c->name, mask, FL_NICK, false);
      }
    } else {
      rremove(c, old_nick);
    }
    c->enf_dirty = true;
  }
}

/* --- MODE events (who did what) --------------------------------------------- */

static bool ban_hits_authorised(bot_state_t *state, const chan_t *c,
                                const char *mask) {
  for (int i = 0; i < c->roster_count; i++)
    if (entry_authorised(state, &c->roster[i]) &&
        auth_wildcard_match(mask, c->roster[i].hostmask))
      return true;
  return false;
}

static void on_mode(bot_state_t *state, const char *chan, const char *prefix,
                    const char *modes, char *args) {
  chan_t *c = chan ? channel_find(state, chan) : NULL;
  if (!c || c->status != C_IN || !modes)
    return;
  bool user_src = prefix && strchr(prefix, '!');
  bool server_src = prefix && !user_src;
  bool src_unauth = user_src && !chanenf_chan_nuh_authorised(state, c, prefix);
  bool src_me = false;
  if (user_src) {
    char sn[MAX_MEMBER_NICK];
    src_me = nuh_nick(prefix, sn, sizeof(sn)) && is_me(state, sn);
  }
  bool bitch = chancfg_get(state, c, CS_BITCH) != 0;
  bool protect = chancfg_get(state, c, CS_PROTECTOPS) != 0;
  bool rev = chancfg_get(state, c, CS_REVENGE) != 0;
  bool nethack = chancfg_get(state, c, CS_STOPNETHACK) != 0;
  bool has_h = strchr(state->isup.prefix_modes, 'h') != NULL;
  bool mode_changed = false, bans_changed = false, revenged = false;

  char *save = NULL;
  char empty[1] = "";
  char *arg = strtok_r(args ? args : empty, " ", &save);
  bool adding = true;
  for (const char *m = modes; *m; m++) {
    char ch = *m;
    if (ch == '+') { adding = true; continue; }
    if (ch == '-') { adding = false; continue; }
    bool has_arg = isupport_mode_has_arg(state, ch, adding);
    char *a = NULL;
    if (has_arg && arg) {
      a = arg;
      arg = strtok_r(NULL, " ", &save);
    }
    if (has_arg && !a && ch != 'k')
      continue;
    /* our own acts coming back end their pending window (recent_ack) */
    if (a && valid_nick(state, a) && ch == 'o')
      recent_ack(state, c, adding ? "reop" : "deop", a);
    else if (a && valid_nick(state, a) && ch == 'h' && !adding)
      recent_ack(state, c, "dehalf", a);
    else if (a && ch == 'b' && !adding && safe_token(a, BAN_MASK_MAX))
      recent_ack(state, c, "unban", a);
    else if (src_me && ch == 'l')
      recent_ack(state, c, "limit", "");
    /* op floods (§8): a user source only, never the server (netjoin) */
    if (user_src && !adding && ch == 'o' && a && valid_nick(state, a)) {
      roster_entry_t *ve = rfind(c, a);
      chanflood_event(state, c->name, prefix, FL_DEOP,
                      ve && (is_me(state, ve->nick) || entry_authorised(state, ve)));
    } else if (user_src && adding && ch == 'b' && a &&
               safe_token(a, BAN_MASK_MAX)) {
      chanflood_event(state, c->name, prefix, FL_BAN,
                      ban_hits_authorised(state, c, a));
    }
    if (ch == 'o' && a && valid_nick(state, a)) {
      roster_entry_t *e = rfind(c, a);
      if (!e || is_me(state, e->nick))
        continue;
      bool auth = entry_authorised(state, e);
      if (adding && !auth) {
        if (bitch)
          job_submit(state, c, JA_DEOP, e->nick, "bitch");
        else if (nethack && server_src)
          job_submit(state, c, JA_DEOP, e->nick, "stopnethack");
      } else if (!adding && auth && user_src && src_unauth && !src_me) {
        if (protect)
          job_submit(state, c, JA_REOP, e->nick, "protectops");
        if (rev && !revenged) {
          revenged = true;
          revenge(state, c, prefix);
        }
      }
    } else if (ch == 'h' && adding && has_h && a && valid_nick(state, a)) {
      roster_entry_t *e = rfind(c, a);
      if (bitch && e && !is_me(state, e->nick) && !entry_authorised(state, e))
        job_submit(state, c, JA_DEHALF, e->nick, "bitch");
    } else if (ch == 'b') {
      bans_changed = true;
      if (adding && a && rev && !revenged && src_unauth && !src_me &&
          safe_token(a, BAN_MASK_MAX) && ban_hits_authorised(state, c, a)) {
        revenged = true;
        revenge(state, c, prefix);
      }
    } else if (strchr("imnpstkl", ch)) {
      mode_changed = true;
      if (ch == 'l' && adding && (server_src || !src_unauth)) {
        c->enf_last_limit = time(NULL); /* limitdelay counts from here */
        /* someone set it: a backup's queued limit job is stale, and fired
         * after the next joins it would race the holder for the same value */
        jobs_drop(state, c, JA_LIMIT);
      }
    }
  }
  if (mode_changed) {
    char sum[64];
    bool clean = c->live_known &&
                 chanmode_sync(state, c, chancfg_get(state, c, CS_DYNAMICLIMIT) != 0,
                               true, true, sum, sizeof(sum)) <= 0;
    /* a line that leaves the channel as stored (the holder's revert echoed)
     * ends a backup's wait: a revert job left pending would keep its first
     * timer and fire on the next operator change just as the holder answers
     * it, so a backup's delay always counts from the newest need */
    if (clean)
      jobs_drop(state, c, JA_MODE);
    else if (!src_me && chancfg_get(state, c, CS_ENFORCEMODES))
      job_submit(state, c, JA_MODE, "", "enforcemodes");
    /* our own revert coming back ends its window once nothing is left to move
     * (a second MODE line may still be in flight): the holder must not leave
     * the next change to a backup for RECENT_MODE_MS */
    if (clean && src_me)
      recent_ack(state, c, "moderevert", "");
  }
  if (bans_changed)
    c->enf_dirty = true;
}

/* --- the state sweep ---------------------------------------------------------- */

/* The unauthorised members `mask` matches (up to max into hits; the count is
 * of all).  auth_hit, when given, is set if an authorised member matches it
 * too.  Authorisation is the roster's cached bit, so this is one wildcard
 * match per member. */
static int unauth_match(bot_state_t *state, const chan_t *c, const char *mask,
                        const roster_entry_t **hits, int max, bool *auth_hit) {
  int n = 0;
  if (auth_hit)
    *auth_hit = false;
  for (int i = 0; i < c->roster_count; i++) {
    const roster_entry_t *e = &c->roster[i];
    if (entry_authorised(state, e)) {
      if (auth_hit && !*auth_hit && auth_wildcard_match(mask, e->hostmask))
        *auth_hit = true;
      continue;
    }
    if (!auth_wildcard_match(mask, e->hostmask))
      continue;
    if (n < max)
      hits[n] = e;
    n++;
  }
  return n;
}

/* Queue kicks for the matched members, at most ENF_KICKS_PER_SWEEP per
 * channel per ban sweep; one whose KICK is still pending does not count. */
static void sweep_kicks(bot_state_t *state, chan_t *c,
                        const roster_entry_t **hits, int n, const char *reason,
                        int *kicks) {
  for (int h = 0; h < n && h < MAX_ROSTER_SIZE && *kicks < ENF_KICKS_PER_SWEEP;
       h++) {
    char nk[MAX_MEMBER_NICK];
    snprintf(nk, sizeof(nk), "%s", hits[h]->nick);
    if (recent_peek(state, c, "kick", nk, RECENT_ACT_MS))
      continue;
    (*kicks)++;
    job_submit(state, c, JA_KICK, nk, reason);
  }
}

static void ban_sweep(bot_state_t *state, chan_t *c, time_t now) {
  if (!c->ban_list_known)
    return;
  bool protect = chancfg_get(state, c, CS_PROTECTOPS) != 0;
  bool enforce = chancfg_get(state, c, CS_ENFORCEBANS) != 0;
  bool dyn = chancfg_get(state, c, CS_DYNAMICBANS) != 0;
  long idle = chancfg_get(state, c, CS_BANIDLE) * 60;
  int kicks = 0;
  /* a job that runs now sends through irc_printf, which can drop the link
   * and free c->bans: masks are copied out before every job_submit */
  char bm[BAN_MASK_MAX + 1];

  /* (a) bans on the channel that match an authorised member (§6.2 step 5) */
  if (protect)
    for (int i = 0; i < c->ban_count; i++) {
      if (strlen(c->bans[i].mask) > BAN_MASK_MAX)
        continue;
      snprintf(bm, sizeof(bm), "%s", c->bans[i].mask);
      if (ban_hits_authorised(state, c, bm))
        job_submit(state, c, JA_UNBAN, bm, "protectops");
    }

  /* (b) the network list for this channel */
  const cfg_ban_t *recs[MAX_BANS_PER_CHAN + MAX_GLOBAL_BANS];
  int nrec = chancfg_bans_for(state, c->name, recs, MAX_BANS_PER_CHAN + MAX_GLOBAL_BANS);
  int order[MAX_BANS_PER_CHAN + MAX_GLOBAL_BANS];
  for (int i = 0; i < nrec; i++) {
    /* permanent first, oldest first: they win the room when the list is full */
    int j = i - 1;
    while (j >= 0 &&
           ((recs[order[j]]->expires != 0) > (recs[i]->expires != 0) ||
            ((recs[order[j]]->expires != 0) == (recs[i]->expires != 0) &&
             recs[order[j]]->ts > recs[i]->ts))) {
      order[j + 1] = order[j];
      j--;
    }
    order[j + 1] = i;
  }
  int room = isupport_ban_cap(state) - c->ban_count;
  for (int k = 0; k < nrec; k++) {
    const cfg_ban_t *r = recs[order[k]];
    if (!safe_token(r->mask, BAN_MASK_MAX))
      continue;
    char rreason[BAN_REASON_MAX + 1];
    snprintf(bm, sizeof(bm), "%s", r->mask);
    snprintf(rreason, sizeof(rreason), "%s", r->reason);
    bool sticky = strchr(r->flags, 's') != NULL;
    /* t moves when act_ban grows the table: read it now, before any job */
    ban_track_t *t = track_get(state, c->name, bm, now);
    if (t->checked_at && now - t->checked_at < 60 && !t->overlap_ok)
      continue; /* known to hit a bot / operator: neither set nor kick */
    time_t last_match = t->last_match;
    bool live = live_has_ban(c, bm);
    const roster_entry_t *hits[MAX_ROSTER_SIZE];
    int nhit = unauth_match(state, c, bm, hits, MAX_ROSTER_SIZE, NULL);
    bool match = nhit > 0;
    if (match)
      t->last_match = now;
    bool keep = sticky || !dyn;
    if (keep && !live) {
      if (sticky || room > 0) {
        room--;
        job_submit(state, c, JA_BAN_MASK, bm, rreason);
      } else {
        keep = false; /* no room: this one stays dynamic */
        if (!c->ban_cap_warned) {
          c->ban_cap_warned = true;
          log_message(L_INFO, state,
                      "[BAN] %s: the server ban list (%d) is full; the rest "
                      "of the listed bans stay dynamic\n", c->name,
                      isupport_ban_cap(state));
        }
      }
    }
    if (!keep) {
      if (match && !live)
        job_submit(state, c, JA_BAN_MASK, bm, rreason);
      else if (live && !match && idle > 0 && now - last_match >= idle)
        job_submit(state, c, JA_UNBAN, bm, "banidle");
    }
    if (match)
      sweep_kicks(state, c, hits, nhit, rreason[0] ? rreason : "banned", &kicks);
  }

  /* (c) records that expired or were deleted: lift them from the channel */
  for (int i = 0; i < state->cfg_ban_count; i++) {
    const cfg_ban_t *b = &state->cfg_bans[i];
    if (b->active && !(b->expires > 0 && b->expires <= now))
      continue;
    if (strcmp(b->chan, "*") != 0 && strcasecmp(b->chan, c->name) != 0)
      continue;
    if (live_has_ban(c, b->mask)) {
      char why[16];
      snprintf(why, sizeof(why), "%s", b->active ? "expired" : "removed");
      snprintf(bm, sizeof(bm), "%s", b->mask);
      job_submit(state, c, JA_UNBAN, bm, why);
    }
  }

  /* (d) +enforcebans: anyone's ban kicks the unauthorised members it matches,
   * except a ban that also hits an authorised member: step (a) takes that one
   * off, and it must not be used to kick in the meantime */
  if (enforce) {
    for (int i = 0; i < c->ban_count; i++) {
      const roster_entry_t *hits[MAX_ROSTER_SIZE];
      if (!safe_token(c->bans[i].mask, BAN_MASK_MAX))
        continue;
      snprintf(bm, sizeof(bm), "%s", c->bans[i].mask);
      bool auth_hit;
      int nhit = unauth_match(state, c, bm, hits, MAX_ROSTER_SIZE, &auth_hit);
      if (nhit == 0 || auth_hit)
        continue;
      sweep_kicks(state, c, hits, nhit, "banned", &kicks);
    }
  }
}

static void cycle_check(bot_state_t *state, chan_t *c, time_t now) {
  if (!chancfg_get(state, c, CS_CYCLE) || c->i_am_opped || c->roster_count != 1 ||
      !is_me(state, c->roster[0].nick) || c->last_who_request == 0 ||
      now - c->last_who_request < 30 ||
      now - c->enf_last_cycle < ENF_CYCLE_MIN_SECS)
    return;
  c->enf_last_cycle = now;
  log_message(L_INFO, state, "[CYCLE] Alone and opless in %s; cycling\n", c->name);
  irc_printf(state, "PART %s :cycling\r\n", c->name);
}

static void chan_sweep(bot_state_t *state, chan_t *c, time_t now) {
  if (!c->i_am_opped) {
    cycle_check(state, c, now);
    return;
  }
  /* +bitch: unauthorised ops already there when we got ops / settings changed */
  if (c->enf_ops_check) {
    c->enf_ops_check = false;
    if (chancfg_get(state, c, CS_BITCH)) {
      bool has_h = strchr(state->isup.prefix_modes, 'h') != NULL;
      for (int i = 0; i < c->roster_count; i++) {
        const roster_entry_t *e = &c->roster[i];
        char nk[MAX_MEMBER_NICK];
        if (entry_authorised(state, e))
          continue;
        snprintf(nk, sizeof(nk), "%s", e->nick);
        if (e->is_op)
          job_submit(state, c, JA_DEOP, nk, "bitch");
        if (has_h && e->is_halfop)
          job_submit(state, c, JA_DEHALF, nk, "bitch");
      }
    }
  }
  if (chancfg_get(state, c, CS_ENFORCEMODES) && c->live_known) {
    char sum[64];
    bool skip = chancfg_get(state, c, CS_DYNAMICLIMIT) != 0;
    if (chanmode_sync(state, c, skip, true, true, sum, sizeof(sum)) > 0)
      job_submit(state, c, JA_MODE, "", "enforcemodes");
  }
  if (chancfg_get(state, c, CS_DYNAMICLIMIT)) {
    long delay = chancfg_get(state, c, CS_LIMITDELAY);
    /* enf_last_limit is the channel's last +l from an authorised source
     * (chanenf_on_mode): one clock for every bot, so the holder is never
     * still inside its own throttle while a backup's has run out */
    if (now - c->enf_last_limit >= delay && limit_due(state, c)) {
      job_submit(state, c, JA_LIMIT, "", "dynamiclimit");
    }
  }
  ban_sweep(state, c, now);
}

static void minute_sweep(bot_state_t *state, time_t now) {
  /* bans this bot wrote and that ran out: write the del (the hub's own sweep
   * does the same; last write wins) */
  for (int i = 0; i < state->cfg_ban_count; i++) {
    cfg_ban_t b = state->cfg_bans[i];
    if (b.active && b.expires > 0 && b.expires <= now && state->bot_uuid[0] &&
        strcmp(b.setter, state->bot_uuid) == 0)
      chancfg_bot_ban(state, b.chan, b.mask, 0, NULL, NULL, true);
  }
  /* idle clocks of bans that are gone from every list */
  for (int i = 0; i < state->ban_track_count; i++) {
    ban_track_t *t = &state->ban_track[i];
    if (!t->chan[0] ||
        (now - t->last_match > 86400 && now - t->set_at > 86400)) {
      *t = state->ban_track[--state->ban_track_count]; /* compact */
      i--;
    }
  }
}

/* What one MODE line or one tick sends (deops, re-ops, bans, a revert) is
 * held and leaves packed: several changes per MODE line. */
void chanenf_on_mode(bot_state_t *state, const char *chan, const char *prefix,
                     const char *modes, char *args) {
  sendq_hold(state);
  on_mode(state, chan, prefix, modes, args);
  sendq_release(state);
}

static void tick(bot_state_t *state);

void chanenf_tick(bot_state_t *state) {
  sendq_hold(state);
  tick(state);
  sendq_release(state);
}

static void tick(bot_state_t *state) {
  if (!(state->status & S_CONNECTED))
    return;
  time_t now = time(NULL);
  long long ms = now_ms();
  bool all = state->cfg_gen != state->enf_seen_gen;
  state->enf_seen_gen = state->cfg_gen;
  for (chan_t *c = state->chanlist; c; c = c->next) {
    if (!c->is_managed || c->status != C_IN)
      continue;
    if (all) {
      c->enf_dirty = true;
      c->enf_ops_check = true;
    }
    bool due = ms - c->enf_last_sweep_ms >= (long long)ENF_SWEEP_SECS * 1000;
    if ((c->enf_dirty && ms - c->enf_last_sweep_ms >= ENF_RESWEEP_MS) || due) {
      c->enf_dirty = false;
      c->enf_last_sweep_ms = ms;
      chan_sweep(state, c, now);
    }
  }
  jobs_tick(state);
  if (now - state->enf_last_minute >= 60) {
    state->enf_last_minute = now;
    minute_sweep(state, now);
  }
}
