/* Channel settings, network defaults and network bans (modes.md §2, §4, §6.3).
 *
 * Three replicated records reach the bot from a hub config push or from its
 * own config file, and all three are parsed here:
 *   C|#chan|<modes>|<settings>|add/del|ts    per-channel (kept in chan_t)
 *   D|<modes>|<settings>|ts                  network defaults (bot_state_t)
 *   B|<#chan|*>|<mask>|<expires>|<flags>|<setter>|<reason>|add/del|ts
 * Each is last-writer-wins on its own stamp.  The settings field is
 * "name=value,name=value"; only overrides appear.  A name this build does not
 * know is kept verbatim in the raw field (so it is written back unchanged)
 * and otherwise ignored.  A known name with an out-of-range value is ignored
 * too: the setting falls back to the next level, never to something unvetted.
 *
 * Reading a value is chancfg_get(): channel override -> D| -> built-in. */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

typedef struct {
  const char *name;
  cset_id_t   id;
  long        lo, hi;      /* flags are 0..1 */
  long        builtin;
  bool        net_only;
} cset_def_t;

/* Built-ins: plan §4 table, §4.1, §9.1. */
static const cset_def_t CSET[CS_COUNT] = {
  {"enforcemodes", CS_ENFORCEMODES, 0, 1, 0, false},
  {"bitch",        CS_BITCH,        0, 1, 0, false},
  {"protectops",   CS_PROTECTOPS,   0, 1, 1, false},
  {"revenge",      CS_REVENGE,      0, 1, 0, false},
  {"stopnethack",  CS_STOPNETHACK,  0, 1, 0, false},
  {"enforcebans",  CS_ENFORCEBANS,  0, 1, 0, false},
  {"dynamicbans",  CS_DYNAMICBANS,  0, 1, 1, false},
  {"dontkickops",  CS_DONTKICKOPS,  0, 1, 1, false},
  {"cycle",        CS_CYCLE,        0, 1, 1, false},
  {"dynamiclimit", CS_DYNAMICLIMIT, 0, 1, 0, false},
  {"bantime",      CS_BANTIME,      0, 525600, 120, false},
  {"bantype",      CS_BANTYPE,      0, 9, 2, false},
  {"banidle",      CS_BANIDLE,      1, 10080, 60, false},
  {"limitgap",     CS_LIMITGAP,     1, 1000, 5, false},
  {"limitdelay",   CS_LIMITDELAY,   10, 3600, 60, false},
  {"ignoretime",   CS_IGNORETIME,   1, 1440, 10, true},
};

static const char *const FL_NAME[FL_COUNT] = {
  "flood chan", "flood ctcp", "flood join", "flood nick", "flood deop",
  "flood kick", "flood ban", "bflood cmd", "bflood msg", "bflood ctcp",
  "sendq",
};
static const int FL_BUILTIN[FL_COUNT][2] = {
  {15, 60}, {3, 60}, {5, 60}, {5, 60}, {3, 10}, {3, 10}, {3, 10},
  {10, 30}, {5, 60}, {3, 60}, {SENDQ_DEF_BURST, SENDQ_DEF_INTERVAL_MS},
};

/* Value bounds of a flood-table entry: n in [nlo,nhi], s in [slo,shi]; `off`
 * is only for the real floods.  sendq is B:I (burst, interval ms). */
static void fl_bounds(int kind, long long *nlo, long long *nhi, long long *slo,
                      long long *shi, bool *off_ok) {
  if (kind == FL_SENDQ) {
    *nlo = SENDQ_MIN_BURST; *nhi = SENDQ_MAX_BURST;
    *slo = SENDQ_MIN_INTERVAL_MS; *shi = SENDQ_MAX_INTERVAL_MS;
    *off_ok = false;
  } else {
    *nlo = 1; *nhi = 1000; *slo = 1; *shi = 3600; *off_ok = true;
  }
}

bool admin_change_refused(const bot_state_t *state) {
  return is_opt_set(state, OPT_HUB_ONLY_MUTATIONS);
}

/* --- small parsers ------------------------------------------------------- */

static bool parse_ll(const char *s, size_t len, long long *out) {
  if (len == 0 || len > 18)
    return false;
  long long v = 0;
  for (size_t i = 0; i < len; i++) {
    if (s[i] < '0' || s[i] > '9')
      return false;
    v = v * 10 + (s[i] - '0');
  }
  *out = v;
  return true;
}

/* No control byte, DEL or '|' (record delimiter). */
static bool plain_text(const char *s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c == 0x7f || c == '|')
      return false;
  }
  return true;
}

static bool valid_chan_name(const char *s, size_t len) {
  if (len < 2 || len >= MAX_CHAN || (s[0] != '#' && s[0] != '&'))
    return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == 0x7f || c == ',' || c == '|')
      return false;
  }
  return true;
}

/* The modes field: printable ASCII only (letters, signs, spaces, a limit). */
static bool valid_modes_field(const char *s, size_t len) {
  if (len > C_MODES_MAX)
    return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c > 0x7e || c == '|')
      return false;
  }
  return true;
}

/* --- settings field ------------------------------------------------------ */

bool chancfg_parse_settings(const char *s, bool net, chan_settings_t *out) {
  memset(out, 0, sizeof(*out));
  size_t total = strlen(s);
  if (total > C_SETTINGS_MAX)
    return false;
  const char *p = s;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    const char *eq = memchr(p, '=', tl);
    if (eq && eq > p) {
      size_t nl = (size_t)(eq - p);
      const char *val = eq + 1;
      size_t vl = tl - nl - 1;
      bool matched = false;
      for (int i = 0; i < CS_COUNT && !matched; i++) {
        if (strlen(CSET[i].name) != nl || memcmp(CSET[i].name, p, nl) != 0)
          continue;
        matched = true;
        long long v;
        if (CSET[i].net_only && !net)
          break; /* not a channel setting: unknown here */
        if (parse_ll(val, vl, &v) && v >= CSET[i].lo && v <= CSET[i].hi) {
          out->present |= 1u << i;
          out->val[i] = (long)v;
        }
      }
      for (int i = 0; i < FL_COUNT && !matched; i++) {
        if (strlen(FL_NAME[i]) != nl || memcmp(FL_NAME[i], p, nl) != 0)
          continue;
        matched = true;
        if (i >= FL_CHAN_COUNT && !net)
          break;
        long long nlo, nhi, slo, shi;
        bool off_ok;
        fl_bounds(i, &nlo, &nhi, &slo, &shi, &off_ok);
        if (off_ok && vl == 3 && memcmp(val, "off", 3) == 0) {
          out->fl[i] = (flood_spec_t){true, true, 0, 0};
        } else {
          const char *colon = memchr(val, ':', vl);
          long long n, sec;
          if (colon && parse_ll(val, (size_t)(colon - val), &n) &&
              parse_ll(colon + 1, vl - (size_t)(colon - val) - 1, &sec) &&
              n >= nlo && n <= nhi && sec >= slo && sec <= shi)
            out->fl[i] = (flood_spec_t){true, false, (int)n, (int)sec};
          else if (i == FL_SENDQ)
            out->bad_sendq = true;
        }
      }
    }
    if (!end)
      break;
    p = end + 1;
  }
  return true;
}

/* --- effective values ---------------------------------------------------- */

long chancfg_get(const bot_state_t *state, const chan_t *c, cset_id_t id) {
  if ((int)id < 0 || id >= CS_COUNT)
    return 0;
  if (!CSET[id].net_only && c && c->cfg_active && c->cfg_ts > 0 &&
      (c->cfg_set.present & (1u << id)))
    return c->cfg_set.val[id];
  if (state->net_ts > 0 && (state->net_set.present & (1u << id)))
    return state->net_set.val[id];
  return CSET[id].builtin;
}

bool chancfg_get_flood(const bot_state_t *state, const chan_t *c,
                       flood_kind_t kind, int *n, int *s) {
  if ((int)kind < 0 || kind >= FL_COUNT)
    return false;
  const flood_spec_t *sp = NULL;
  if (kind < FL_CHAN_COUNT && c && c->cfg_active && c->cfg_ts > 0 &&
      c->cfg_set.fl[kind].present)
    sp = &c->cfg_set.fl[kind];
  else if (state->net_ts > 0 && state->net_set.fl[kind].present)
    sp = &state->net_set.fl[kind];
  if (sp) {
    if (sp->off)
      return false;
    if (n) *n = sp->n;
    if (s) *s = sp->s;
    return true;
  }
  if (n) *n = FL_BUILTIN[kind][0];
  if (s) *s = FL_BUILTIN[kind][1];
  return true;
}

const char *chancfg_get_modes(const bot_state_t *state, const chan_t *c) {
  if (c && c->cfg_active && c->cfg_ts > 0 && c->cfg_modes[0])
    return c->cfg_modes;
  if (state->net_ts > 0 && state->net_modes[0])
    return state->net_modes;
  return "+nt";
}

/* --- field splitting ----------------------------------------------------- */

typedef struct { const char *p; size_t len; } fld_t;

/* Split `data` on '|' into at most `max` fields; the last takes the rest.
 * Returns the number of fields. */
static int split_pipes(const char *data, fld_t *f, int max) {
  int n = 0;
  const char *p = data;
  while (n < max) {
    const char *bar = (n == max - 1) ? NULL : strchr(p, '|');
    f[n].p = p;
    f[n].len = bar ? (size_t)(bar - p) : strlen(p);
    n++;
    if (!bar)
      break;
    p = bar + 1;
  }
  return n;
}

static bool is_add_op(const fld_t *f, bool *add) {
  if (f->len == 3 && memcmp(f->p, "add", 3) == 0) { *add = true; return true; }
  if (f->len == 3 && memcmp(f->p, "del", 3) == 0) { *add = false; return true; }
  return false;
}

/* --- C| ------------------------------------------------------------------ */

bool chancfg_apply_c_line(bot_state_t *state, const char *data) {
  if (strlen(data) > C_LINE_MAX)
    return false;
  fld_t f[6];
  int n = split_pipes(data, f, 6);
  if (n < 5)
    return false;
  bool add;
  long long ts;
  if (!valid_chan_name(f[0].p, f[0].len) || !valid_modes_field(f[1].p, f[1].len) ||
      f[2].len > C_SETTINGS_MAX || !plain_text(f[2].p, f[2].len) ||
      !is_add_op(&f[3], &add) || !parse_ll(f[4].p, f[4].len, &ts) || ts <= 0)
    return false;

  char name[MAX_CHAN];
  memcpy(name, f[0].p, f[0].len);
  name[f[0].len] = '\0';
  chan_t *c = channel_find(state, name);
  if (!c) {
    if (!add)
      return false; /* a delete for a channel we never heard of */
    c = channel_add(state, name);
    if (!c)
      return false;
    /* Settings before the channel record: held unmanaged (never joined)
     * until its c| add arrives and wins LWW against timestamp 0. */
    c->is_managed = false;
    c->timestamp = 0;
  }
  if (!lww_accepts((time_t)ts, add, c->cfg_ts, c->cfg_active))
    return false;

  memcpy(c->cfg_modes, f[1].p, f[1].len);
  c->cfg_modes[f[1].len] = '\0';
  memcpy(c->cfg_settings, f[2].p, f[2].len);
  c->cfg_settings[f[2].len] = '\0';
  chancfg_parse_settings(c->cfg_settings, false, &c->cfg_set);
  c->cfg_ts = (time_t)ts;
  c->cfg_active = add;
  state->cfg_gen++;
  return true;
}

int chancfg_format_c_line(const chan_t *c, char *buf, size_t len) {
  if (c->cfg_ts <= 0)
    return 0;
  int w = snprintf(buf, len, "C|%s|%s|%s|%s|%lld\n", c->name, c->cfg_modes,
                   c->cfg_settings, c->cfg_active ? "add" : "del",
                   (long long)c->cfg_ts);
  return (w < 0 || (size_t)w >= len) ? -1 : w;
}

/* --- D| ------------------------------------------------------------------ */

bool chancfg_apply_d_line(bot_state_t *state, const char *data) {
  if (strlen(data) > D_LINE_MAX)
    return false;
  fld_t f[3];
  int n = split_pipes(data, f, 3);
  long long ts;
  if (n < 3 || !valid_modes_field(f[0].p, f[0].len) ||
      f[1].len > D_SETTINGS_MAX || !plain_text(f[1].p, f[1].len) ||
      !parse_ll(f[2].p, f[2].len, &ts) || ts <= 0)
    return false;

  char modes[C_MODES_MAX + 1], sets[D_SETTINGS_MAX + 1];
  memcpy(modes, f[0].p, f[0].len);
  modes[f[0].len] = '\0';
  memcpy(sets, f[1].p, f[1].len);
  sets[f[1].len] = '\0';

  /* One record, no op: newer stamp wins; on a tie the greater string wins
   * (same rule as the opt flags, so every node settles on the same one). */
  if ((time_t)ts < state->net_ts)
    return false;
  if ((time_t)ts == state->net_ts) {
    char cur[C_MODES_MAX + D_SETTINGS_MAX + 2], inc[C_MODES_MAX + D_SETTINGS_MAX + 2];
    snprintf(cur, sizeof(cur), "%s|%s", state->net_modes, state->net_settings);
    snprintf(inc, sizeof(inc), "%s|%s", modes, sets);
    if (strcmp(inc, cur) <= 0)
      return false;
  }
  memcpy(state->net_modes, modes, sizeof(state->net_modes));
  memcpy(state->net_settings, sets, sizeof(state->net_settings));
  flood_spec_t old_sq = state->net_set.fl[FL_SENDQ];
  chancfg_parse_settings(state->net_settings, true, &state->net_set);
  state->net_ts = (time_t)ts;
  if (state->net_set.bad_sendq) {
    /* Bad sendq value: ignore it, keep the one in force. */
    state->net_set.fl[FL_SENDQ] = old_sq;
    log_message(L_INFO, state,
                "[SENDQ] Ignoring bad D| sendq value (want B:I, B 1..100, "
                "I 0..10000ms); keeping %d:%d\n",
                state->sendq.burst, state->sendq.interval_ms);
  } else {
    int b = SENDQ_DEF_BURST, iv = SENDQ_DEF_INTERVAL_MS;
    chancfg_get_flood(state, NULL, FL_SENDQ, &b, &iv);
    sendq_set_limits(state, b, iv);
  }
  state->cfg_gen++;
  return true;
}

int chancfg_format_d_line(const bot_state_t *state, char *buf, size_t len) {
  if (state->net_ts <= 0)
    return 0;
  int w = snprintf(buf, len, "D|%s|%s|%lld\n", state->net_modes,
                   state->net_settings, (long long)state->net_ts);
  return (w < 0 || (size_t)w >= len) ? -1 : w;
}

/* --- B| ------------------------------------------------------------------ */

static cfg_ban_t *ban_find(bot_state_t *state, const char *chan,
                           const char *mask) {
  for (int i = 0; i < state->cfg_ban_count; i++) {
    cfg_ban_t *b = &state->cfg_bans[i];
    if (strcasecmp(b->chan, chan) == 0 && strcasecmp(b->mask, mask) == 0)
      return b;
  }
  return NULL;
}

/* Room for one more active ban on `chan` under the per-channel / global caps. */
static bool ban_active_room(const bot_state_t *state, const char *chan) {
  int n = 0;
  for (int i = 0; i < state->cfg_ban_count; i++) {
    const cfg_ban_t *b = &state->cfg_bans[i];
    if (b->active && strcasecmp(b->chan, chan) == 0)
      n++;
  }
  if (strcmp(chan, "*") == 0)
    return n < MAX_GLOBAL_BANS;
  return n < MAX_BANS_PER_CHAN;
}

/* A slot for a new entry: grows the table up to CFG_MAX_BANS, then reuses the
 * oldest tombstone.  NULL when the table is full of live bans. */
static cfg_ban_t *ban_slot(bot_state_t *state) {
  if (state->cfg_ban_count < state->cfg_ban_cap)
    return &state->cfg_bans[state->cfg_ban_count++];
  if (state->cfg_ban_cap < CFG_MAX_BANS) {
    int cap = state->cfg_ban_cap ? state->cfg_ban_cap * 2 : 16;
    if (cap > CFG_MAX_BANS)
      cap = CFG_MAX_BANS;
    cfg_ban_t *nb = realloc(state->cfg_bans, (size_t)cap * sizeof(*nb));
    if (!nb)
      return NULL;
    state->cfg_bans = nb;
    state->cfg_ban_cap = cap;
    return &state->cfg_bans[state->cfg_ban_count++];
  }
  int oldest = -1;
  for (int i = 0; i < state->cfg_ban_count; i++)
    if (!state->cfg_bans[i].active &&
        (oldest < 0 || state->cfg_bans[i].ts < state->cfg_bans[oldest].ts))
      oldest = i;
  return oldest < 0 ? NULL : &state->cfg_bans[oldest];
}

/* Store `in` under LWW.  True when the table changed. */
static bool ban_store(bot_state_t *state, const cfg_ban_t *in) {
  cfg_ban_t *b = ban_find(state, in->chan, in->mask);
  if (b) {
    if (!lww_accepts(in->ts, in->active, b->ts, b->active))
      return false;
    if (in->active && !b->active && !ban_active_room(state, in->chan))
      return false;
    *b = *in;
    state->cfg_gen++;
    return true;
  }
  if (in->active && !ban_active_room(state, in->chan))
    return false;
  b = ban_slot(state);
  if (!b)
    return false;
  *b = *in;
  state->cfg_gen++;
  return true;
}

bool chancfg_apply_b_line(bot_state_t *state, const char *data) {
  size_t dl = strlen(data);
  if (dl > B_LINE_MAX)
    return false;
  /* op and ts are the last two fields; the reason between is everything the
   * hub put there, kept whole. */
  const char *last = strrchr(data, '|');
  if (!last || last == data)
    return false;
  const char *prev = last - 1;
  while (prev > data && *prev != '|')
    prev--;
  if (*prev != '|')
    return false;
  fld_t opf = {prev + 1, (size_t)(last - prev - 1)};
  fld_t tsf = {last + 1, strlen(last + 1)};
  size_t headlen = (size_t)(prev - data);
  char head[B_LINE_MAX + 1];
  memcpy(head, data, headlen);
  head[headlen] = '\0';

  fld_t f[6];
  int n = split_pipes(head, f, 6);
  bool add;
  long long ts, expires;
  if (n < 6 || !is_add_op(&opf, &add) || !parse_ll(tsf.p, tsf.len, &ts) ||
      ts <= 0)
    return false;
  bool all = (f[0].len == 1 && f[0].p[0] == '*');
  if (!all && !valid_chan_name(f[0].p, f[0].len))
    return false;
  if (f[1].len == 0 || f[1].len > BAN_MASK_MAX || !plain_text(f[1].p, f[1].len) ||
      memchr(f[1].p, ' ', f[1].len))
    return false;
  if (!parse_ll(f[2].p, f[2].len, &expires))
    return false;
  if (f[3].len >= sizeof(((cfg_ban_t *)0)->flags) || !plain_text(f[3].p, f[3].len))
    return false;
  if (f[4].len > BAN_SETTER_MAX || !plain_text(f[4].p, f[4].len))
    return false;
  /* The reason is the sixth field of head: all that remains.  It may not
   * hold control bytes, and is at most BAN_REASON_MAX. */
  if (f[5].len > BAN_REASON_MAX)
    return false;
  for (size_t i = 0; i < f[5].len; i++) {
    unsigned char c = (unsigned char)f[5].p[i];
    if (c < 0x20 || c == 0x7f)
      return false;
  }

  cfg_ban_t b;
  memset(&b, 0, sizeof(b));
  memcpy(b.chan, f[0].p, f[0].len);
  memcpy(b.mask, f[1].p, f[1].len);
  memcpy(b.flags, f[3].p, f[3].len);
  memcpy(b.setter, f[4].p, f[4].len);
  memcpy(b.reason, f[5].p, f[5].len);
  b.expires = (time_t)expires;
  b.ts = (time_t)ts;
  b.active = add;
  return ban_store(state, &b);
}

int chancfg_format_b_line(const cfg_ban_t *b, char *buf, size_t len) {
  int w = snprintf(buf, len, "B|%s|%s|%lld|%s|%s|%s|%s|%lld\n", b->chan,
                   b->mask, (long long)b->expires, b->flags, b->setter,
                   b->reason, b->active ? "add" : "del", (long long)b->ts);
  return (w < 0 || (size_t)w >= len) ? -1 : w;
}

int chancfg_purge_bans(bot_state_t *state, time_t cutoff) {
  int removed = 0;
  for (int i = 0; i < state->cfg_ban_count; i++) {
    cfg_ban_t *b = &state->cfg_bans[i];
    if (!b->active && (cutoff == 0 || b->ts < cutoff)) {
      state->cfg_bans[i] = state->cfg_bans[--state->cfg_ban_count];
      removed++;
      i--;
    }
  }
  return removed;
}

int chancfg_bans_for(const bot_state_t *state, const char *chan,
                     const cfg_ban_t **out, int max) {
  int n = 0;
  time_t now = time(NULL);
  for (int i = 0; i < state->cfg_ban_count && n < max; i++) {
    const cfg_ban_t *b = &state->cfg_bans[i];
    if (!b->active || (b->expires > 0 && b->expires <= now))
      continue;
    if (strcmp(b->chan, "*") == 0 || strcasecmp(b->chan, chan) == 0)
      out[n++] = b;
  }
  return n;
}

/* A ban this bot sets on its own (flood, revenge): stored, pushed to the hub
 * as a bot-written B| (hub rules: timed, <= bantime, setter == our uuid, del
 * only of our own) and saved by the next debounced config flush.  Never
 * gated by opt 'h' -- it is enforcement, not an admin change (D43). */
bool chancfg_bot_ban(bot_state_t *state, const char *chan, const char *mask,
                     time_t expires, const char *flags, const char *reason,
                     bool del) {
  if (!state->bot_uuid[0] || !chan || !mask)
    return false;
  size_t ml = strlen(mask);
  if (ml == 0 || ml > BAN_MASK_MAX || !plain_text(mask, ml) || strchr(mask, ' '))
    return false;
  if (strcmp(chan, "*") != 0 && !valid_chan_name(chan, strlen(chan)))
    return false;
  time_t now = time(NULL);

  cfg_ban_t b;
  memset(&b, 0, sizeof(b));
  snprintf(b.chan, sizeof(b.chan), "%s", chan);
  snprintf(b.mask, sizeof(b.mask), "%s", mask);
  snprintf(b.setter, sizeof(b.setter), "%s", state->bot_uuid);
  cfg_ban_t *old = ban_find(state, b.chan, b.mask);
  if (del) {
    if (!old || !old->active || strcmp(old->setter, state->bot_uuid) != 0)
      return false;
    b = *old;
    b.active = false;
    b.ts = lww_next_ts(old->ts);
  } else {
    if (expires <= now)
      return false; /* the hub takes only timed bot bans */
    if (old && old->active && strcmp(old->setter, state->bot_uuid) != 0)
      return false; /* never overwrite another setter's active ban (hub rule) */
    chan_t *c = (b.chan[0] == '#' || b.chan[0] == '&')
                    ? channel_find(state, b.chan) : NULL;
    long bt = chancfg_get(state, c, CS_BANTIME);
    if (bt > 0 && expires > now + bt * 60)
      expires = now + bt * 60;
    b.expires = expires;
    b.active = true;
    b.ts = old ? lww_next_ts(old->ts) : now;
    if (flags)
      snprintf(b.flags, sizeof(b.flags), "%s", flags);
    if (reason) {
      size_t k = 0;
      for (const char *r = reason; *r && k < BAN_REASON_MAX; r++)
        b.reason[k++] = ((unsigned char)*r < 0x20 || *r == 0x7f || *r == '|')
                            ? ' ' : *r;
      b.reason[k] = '\0';
    }
  }
  b.push_pending = true;
  if (!ban_store(state, &b))
    return false;

  char line[B_LINE_MAX + 2];
  int ll = chancfg_format_b_line(&b, line, sizeof(line));
  if (ll > 0 && hub_client_push_lines(state, line, (size_t)ll)) {
    cfg_ban_t *st = ban_find(state, b.chan, b.mask);
    if (st)
      st->push_pending = false;
  }
  state->config_dirty = true;
  return true;
}

/* --- local writes (bot commands, §5.2) ------------------------------------ */

/* Push complete record lines to the hub when linked, and save the config.
 * Best effort: a hub that is down gets the records in the next full push. */
static void local_commit(bot_state_t *state, const char *line, int len) {
  if (len > 0)
    hub_client_push_lines(state, line, (size_t)len);
  state->config_dirty = true;
  for (chan_t *c = state->chanlist; c; c = c->next)
    c->enf_dirty = c->enf_ops_check = true;
}

bool chancfg_local_c(bot_state_t *state, chan_t *c, const char *modes,
                     const char *settings) {
  if (!c || !modes || !settings)
    return false;
  time_t ts = lww_next_ts(c->cfg_ts);
  char data[C_LINE_MAX + 2];
  int w = snprintf(data, sizeof(data), "%s|%s|%s|add|%lld", c->name, modes,
                   settings, (long long)ts);
  if (w < 0 || (size_t)w >= sizeof(data) || !chancfg_apply_c_line(state, data))
    return false;
  char line[C_LINE_MAX + 4];
  int n = chancfg_format_c_line(c, line, sizeof(line));
  local_commit(state, line, n);
  return true;
}

bool chancfg_local_d(bot_state_t *state, const char *modes,
                     const char *settings) {
  if (!modes || !settings)
    return false;
  time_t ts = lww_next_ts(state->net_ts);
  char data[D_LINE_MAX + 2];
  int w = snprintf(data, sizeof(data), "%s|%s|%lld", modes, settings,
                   (long long)ts);
  if (w < 0 || (size_t)w >= sizeof(data) || !chancfg_apply_d_line(state, data))
    return false;
  char line[D_LINE_MAX + 4];
  int n = chancfg_format_d_line(state, line, sizeof(line));
  local_commit(state, line, n);
  return true;
}

const cfg_ban_t *chancfg_ban_get(const bot_state_t *state, const char *chan,
                                 const char *mask) {
  for (int i = 0; i < state->cfg_ban_count; i++) {
    const cfg_ban_t *b = &state->cfg_bans[i];
    if (b->active && strcasecmp(b->chan, chan) == 0 &&
        strcasecmp(b->mask, mask) == 0)
      return b;
  }
  return NULL;
}

bool chancfg_local_ban(bot_state_t *state, const char *chan, const char *mask,
                       time_t expires, const char *flags, const char *setter,
                       const char *reason, bool del) {
  if (!chan || !mask || !setter)
    return false;
  size_t ml = strlen(mask);
  if (ml == 0 || ml > BAN_MASK_MAX || !plain_text(mask, ml) || strchr(mask, ' '))
    return false;
  if (strcmp(chan, "*") != 0 && !valid_chan_name(chan, strlen(chan)))
    return false;
  size_t sl = strlen(setter);
  if (sl == 0 || sl > BAN_SETTER_MAX || !plain_text(setter, sl))
    return false;
  cfg_ban_t *old = ban_find(state, chan, mask);
  cfg_ban_t b;
  memset(&b, 0, sizeof(b));
  if (del) {
    if (!old || !old->active)
      return false;
    b = *old;
    b.active = false;
    b.ts = lww_next_ts(old->ts);
  } else {
    snprintf(b.chan, sizeof(b.chan), "%s", chan);
    snprintf(b.mask, sizeof(b.mask), "%s", mask);
    snprintf(b.setter, sizeof(b.setter), "%s", setter);
    if (flags)
      snprintf(b.flags, sizeof(b.flags), "%s", flags);
    size_t k = 0;
    for (const char *r = reason ? reason : ""; *r && k < BAN_REASON_MAX; r++)
      b.reason[k++] = ((unsigned char)*r < 0x20 || *r == 0x7f || *r == '|')
                          ? ' ' : *r;
    b.reason[k] = '\0';
    b.expires = expires;
    b.active = true;
    b.ts = old ? lww_next_ts(old->ts) : time(NULL);
  }
  b.push_pending = false;
  if (!ban_store(state, &b))
    return false;
  char line[B_LINE_MAX + 2];
  int n = chancfg_format_b_line(&b, line, sizeof(line));
  local_commit(state, line, n);
  return true;
}

/* --- settings editing and listing ------------------------------------------ */

static int item_index(const char *name, bool net) {
  for (int i = 0; i < CS_COUNT; i++)
    if (strcmp(CSET[i].name, name) == 0)
      return (CSET[i].net_only && !net) ? -1 : i;
  for (int i = 0; i < FL_COUNT; i++)
    if (strcmp(FL_NAME[i], name) == 0)
      return (i >= FL_CHAN_COUNT && !net) ? -1 : CS_COUNT + i;
  return -1;
}

bool chancfg_setting_is_flag(const char *name) {
  int i = item_index(name, true);
  return i >= 0 && i < CS_COUNT && CSET[i].lo == 0 && CSET[i].hi == 1;
}

const char *chancfg_item_name(int idx, bool net) {
  if (idx < 0 || idx >= (int)CS_COUNT + (int)FL_COUNT)
    return NULL;
  if (idx < CS_COUNT)
    return (CSET[idx].net_only && !net) ? NULL : CSET[idx].name;
  return (idx - CS_COUNT >= FL_CHAN_COUNT && !net) ? NULL
                                                    : FL_NAME[idx - CS_COUNT];
}

/* What item idx does, in the same index space as chancfg_item_name (the
 * hub console's help channel set / network set say the same). */
static const char *const ITEM_WHAT[CS_COUNT + FL_COUNT] = {
  "put back any change away from the stored modes",
  "only authorised users and bots may hold ops",
  "re-op an authorised member someone deopped; lift bans on one",
  "deop whoever deops, kicks or bans an authorised member; again: kick + ban",
  "take back ops a netsplit rejoin gave to unauthorised members",
  "kick the unauthorised members a new ban matches",
  "set a listed ban only while someone it matches is in the channel",
  "ops are never acted on for chan, ctcp, join and nick floods",
  "a bot alone in a channel with no ops parts and rejoins for ops",
  "keep +l at the member count plus limitgap",
  "minutes an automatic ban (flood, revenge) lasts; 0 = permanent",
  "ban mask shape 0-9: 2 = *!*@host, 4 = *!*@*.host, 7 = nick!*@host",
  "dynamicbans: minutes with no match before a listed ban is lifted",
  "dynamiclimit: free places above the member count",
  "dynamiclimit: seconds between limit changes",
  "minutes a flooding host or user stays ignored",
  "messages to the channel per host: kick, again: ban",
  "CTCPs to the channel per host: kick, again: ban",
  "joins per host (join/part cycling): ban + kick",
  "nick changes per host: kick, again: ban",
  "deops by an unauthorised op: deop them, re-op the victims",
  "kicks by an unauthorised op: deop them, again: kick + ban",
  "bans by an unauthorised op: deop them, lift bans on authorised",
  "commands per user: extras dropped; 3x the rate ignores the user",
  "other messages to a bot per host: the host is ignored",
  "CTCPs to a bot per host: the host is ignored",
  "a bot's IRC output: B lines at once, then one every I ms",
};

/* Item idx's built-in value as typed (on/off, a number, N:S) and what it
 * does; false for an index past the end. */
bool chancfg_item_help(int idx, char *def, size_t def_size, const char **what) {
  if (idx < 0 || idx >= (int)CS_COUNT + (int)FL_COUNT)
    return false;
  if (idx < CS_COUNT) {
    if (CSET[idx].hi == 1)
      snprintf(def, def_size, "%s", CSET[idx].builtin ? "on" : "off");
    else
      snprintf(def, def_size, "%ld", CSET[idx].builtin);
  } else {
    int k = idx - CS_COUNT;
    snprintf(def, def_size, "%d:%d", FL_BUILTIN[k][0], FL_BUILTIN[k][1]);
  }
  *what = ITEM_WHAT[idx];
  return true;
}

int chancfg_item_source(const bot_state_t *state, const chan_t *c, int idx) {
  bool chan_ok = c && c->cfg_active && c->cfg_ts > 0;
  bool net_ok = state->net_ts > 0;
  if (idx < CS_COUNT)
    return (chan_ok && !CSET[idx].net_only &&
            (c->cfg_set.present & (1u << idx))) ? 2
         : (net_ok && (state->net_set.present & (1u << idx))) ? 1 : 0;
  int k = idx - CS_COUNT;
  if (k < 0 || k >= FL_COUNT)
    return 0;
  return (chan_ok && k < FL_CHAN_COUNT && c->cfg_set.fl[k].present) ? 2
       : (net_ok && state->net_set.fl[k].present) ? 1 : 0;
}

bool chancfg_settings_edit(char *settings, size_t cap, bool net,
                           const char *name, const char *value, char *why,
                           size_t why_size) {
  int idx = item_index(name, net);
  if (idx < 0) {
    snprintf(why, why_size, "unknown setting '%s'", name);
    return false;
  }
  bool drop = strcmp(value, "default") == 0;
  char nv[48];
  if (!drop) {
    size_t vl = strlen(value);
    if (idx < CS_COUNT) {
      long long v;
      if (!parse_ll(value, vl, &v) || v < CSET[idx].lo || v > CSET[idx].hi) {
        snprintf(why, why_size, "%s must be %ld..%ld", name, CSET[idx].lo,
                 CSET[idx].hi);
        return false;
      }
      snprintf(nv, sizeof(nv), "%lld", v);
    } else if (idx - CS_COUNT != FL_SENDQ && strcmp(value, "off") == 0) {
      snprintf(nv, sizeof(nv), "off");
    } else {
      const char *colon = strchr(value, ':');
      long long n, sec, nlo, nhi, slo, shi;
      bool off_ok;
      fl_bounds(idx - CS_COUNT, &nlo, &nhi, &slo, &shi, &off_ok);
      if (!colon || !parse_ll(value, (size_t)(colon - value), &n) ||
          !parse_ll(colon + 1, strlen(colon + 1), &sec) || n < nlo || n > nhi ||
          sec < slo || sec > shi) {
        if (off_ok)
          snprintf(why, why_size, "%s must be N:S (N 1..1000, S 1..3600), off "
                   "or default", name);
        else
          snprintf(why, why_size, "%s must be B:I (burst 1..100, interval "
                   "0..10000 ms) or default", name);
        return false;
      }
      snprintf(nv, sizeof(nv), "%lld:%lld", n, sec);
    }
  }
  char out[D_SETTINGS_MAX + 64];
  size_t ol = 0, nl = strlen(name);
  out[0] = '\0';
  const char *p = settings;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    bool same = tl > nl && memcmp(p, name, nl) == 0 && p[nl] == '=';
    if (!same && tl > 0) {
      if (ol + tl + 2 >= sizeof(out))
        goto full;
      if (ol)
        out[ol++] = ',';
      memcpy(out + ol, p, tl);
      ol += tl;
      out[ol] = '\0';
    }
    if (!end)
      break;
    p = end + 1;
  }
  if (!drop) {
    int w = snprintf(out + ol, sizeof(out) - ol, "%s%s=%s", ol ? "," : "", name,
                     nv);
    if (w < 0 || (size_t)w >= sizeof(out) - ol)
      goto full;
    ol += (size_t)w;
  }
  size_t field_max = C_SETTINGS_MAX;
  if (net)
    field_max = D_SETTINGS_MAX;
  if (ol >= cap || ol > field_max)
    goto full;
  memcpy(settings, out, ol + 1);
  return true;
full:
  snprintf(why, why_size, "settings field is full");
  return false;
}

void chancfg_free(bot_state_t *state) {
  free(state->cfg_bans);
  state->cfg_bans = NULL;
  state->cfg_ban_count = state->cfg_ban_cap = 0;
  free(state->ban_track);
  state->ban_track = NULL;
  state->ban_track_count = state->ban_track_cap = 0;
}
