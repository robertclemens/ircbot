/* access.c — admin flags (uf|) and oper channel bindings (uc|) on the bot.
 *
 * irchub docs/plans/2026-10-16_user_flags_plan.md §3; mirrors irchub
 * hub_access.c record for record (same lines, same LWW, same migration), so a
 * bot, its hub and a hubless network agree.  Fail closed: no flags record =
 * no flags, no live binding = no channel access.  Every writer (config load,
 * hub config, local commands) goes through access_uflag_put / access_uchan_put,
 * which validate and cap every field. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "bot.h"

static bool uuid_shape(const char *u) {
  if (!u || strlen(u) != 36) return false;
  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (u[i] != '-') return false;
    } else if (!isxdigit((unsigned char)u[i])) {
      return false;
    }
  }
  return true;
}

bool access_flags_canon(const char *in, char *out, size_t cap) {
  if (!in || !out || cap < USER_FLAGS_MAX + 1) return false;
  bool have[sizeof(USER_FLAG_LETTERS)] = {false};
  for (const char *p = in; *p; p++) {
    const char *at = strchr(USER_FLAG_LETTERS, *p);
    if (!at) return false;
    have[at - USER_FLAG_LETTERS] = true;
  }
  size_t o = 0;
  for (size_t i = 0; i < sizeof(USER_FLAG_LETTERS) - 1; i++)
    if (have[i]) out[o++] = USER_FLAG_LETTERS[i];
  out[o] = '\0';
  return true;
}

/* "+c-u" edits cur; "chu" / "+chu" / "+a" replaces it (irchub
 * hub_uflags_edit). */
bool access_flags_edit(const char *cur, const char *spec, char *out, size_t cap) {
  if (!spec || !spec[0] || cap < USER_FLAGS_MAX + 1) return false;
  if (!strchr(spec, '-'))
    return access_flags_canon(spec[0] == '+' ? spec + 1 : spec, out, cap) &&
           (spec[0] != '+' || spec[1]);
  char work[USER_FLAGS_MAX + 1];
  if (!access_flags_canon(cur ? cur : "", work, sizeof(work))) work[0] = '\0';
  bool have[sizeof(USER_FLAG_LETTERS)] = {false};
  for (const char *p = work; *p; p++) have[strchr(USER_FLAG_LETTERS, *p) - USER_FLAG_LETTERS] = true;
  int sign = 0;
  bool any = false;
  for (const char *p = spec; *p; p++) {
    if (*p == '+' || *p == '-') {
      sign = *p == '+' ? 1 : -1;
      continue;
    }
    const char *at = strchr(USER_FLAG_LETTERS, *p);
    if (!at || !sign) return false;
    have[at - USER_FLAG_LETTERS] = sign > 0;
    any = true;
  }
  if (!any) return false;
  size_t o = 0;
  for (size_t i = 0; i < sizeof(USER_FLAG_LETTERS) - 1; i++)
    if (have[i]) out[o++] = USER_FLAG_LETTERS[i];
  out[o] = '\0';
  return true;
}

/* Newer stamp wins; a tie keeps the fewer rights (irchub hub_uflags_accepts). */
bool access_flags_accepts(time_t in_ts, const char *in, time_t cur_ts, const char *cur) {
  if (in_ts != cur_ts) return in_ts > cur_ts;
  bool ia = strchr(in, 'a') != NULL, ca = strchr(cur, 'a') != NULL;
  if (ia != ca) return !ia;
  size_t il = strlen(in), cl = strlen(cur);
  if (il != cl) return il < cl;
  return strcmp(in, cur) < 0;
}

bool access_chan_name_ok(const char *chan) {
  if (!chan || !chan[0]) return false;
  if (strcmp(chan, "*") == 0) return true;
  size_t n = strlen(chan);
  if ((chan[0] != '#' && chan[0] != '&') || n < 2 || n >= MAX_CHAN) return false;
  for (const char *p = chan; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c <= 0x20 || c == 0x7f || c == ',' || c == '|' || c == ':') return false;
  }
  return true;
}

uflag_record_t *access_uflag_find(bot_state_t *state, const char *uuid) {
  for (int i = 0; i < state->uflag_record_count; i++)
    if (strcmp(state->uflag_records[i].uuid, uuid) == 0) return &state->uflag_records[i];
  return NULL;
}

uchan_record_t *access_uchan_find(bot_state_t *state, const char *uuid, const char *chan) {
  for (int i = 0; i < state->uchan_record_count; i++) {
    uchan_record_t *r = &state->uchan_records[i];
    if (strcmp(r->uuid, uuid) == 0 && strcasecmp(r->chan, chan) == 0) return r;
  }
  return NULL;
}

bool access_uflag_put(bot_state_t *state, const char *uuid, const char *flags, time_t ts) {
  char canon[USER_FLAGS_MAX + 1];
  if (!uuid_shape(uuid) || !access_flags_canon(flags, canon, sizeof(canon)) || ts <= 0)
    return false;
  uflag_record_t *r = access_uflag_find(state, uuid);
  if (!r) {
    if (state->uflag_record_count >= MAX_USER_FLAGS) {
      log_message(L_INFO, state, "[ACCESS] Flag table full (%d): uf| for %s dropped\n",
                  MAX_USER_FLAGS, uuid);
      return false;
    }
    r = &state->uflag_records[state->uflag_record_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
  } else if (!access_flags_accepts(ts, canon, r->timestamp, r->flags)) {
    return false;
  }
  snprintf(r->flags, sizeof(r->flags), "%s", canon);
  r->timestamp = ts;
  return true;
}

bool access_uchan_put(bot_state_t *state, const char *uuid, const char *chan, bool active,
                      time_t ts) {
  if (!uuid_shape(uuid) || !access_chan_name_ok(chan) || ts <= 0) return false;
  uchan_record_t *r = access_uchan_find(state, uuid, chan);
  if (!r) {
    if (state->uchan_record_count >= MAX_CHAN_BINDS) {
      log_message(L_INFO, state, "[ACCESS] Binding table full (%d): uc| %s for %s dropped\n",
                  MAX_CHAN_BINDS, chan, uuid);
      return false;
    }
    r = &state->uchan_records[state->uchan_record_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
    snprintf(r->chan, sizeof(r->chan), "%s", chan);
  } else if (!lww_accepts(ts, active, r->timestamp, r->is_active)) {
    return false;
  }
  r->is_active = active;
  r->timestamp = ts;
  return true;
}

const char *access_user_flags(const bot_state_t *state, const char *uuid) {
  for (int i = 0; i < state->uflag_record_count; i++)
    if (strcmp(state->uflag_records[i].uuid, uuid) == 0) return state->uflag_records[i].flags;
  return "";
}

/* 'a' passes every letter. */
bool access_user_has_flag(const bot_state_t *state, const char *uuid, char flag) {
  const char *f = access_user_flags(state, uuid);
  return strchr(f, 'a') != NULL || (flag && strchr(f, flag) != NULL);
}

/* An oper's channel access: a live "*" or a live binding to chan. */
bool access_user_chan_ok(const bot_state_t *state, const char *uuid, const char *chan) {
  for (int i = 0; i < state->uchan_record_count; i++) {
    const uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    if (strcmp(r->chan, "*") == 0 || (chan && strcasecmp(r->chan, chan) == 0)) return true;
  }
  return false;
}

int access_user_chan_count(const bot_state_t *state, const char *uuid, bool *global) {
  int n = 0;
  if (global) *global = false;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    n++;
    if (global && strcmp(r->chan, "*") == 0) *global = true;
  }
  return n;
}

int access_format_uflag(const uflag_record_t *r, char *buf, size_t cap) {
  return snprintf(buf, cap, "uf|%s|%s|%lld\n", r->uuid, r->flags, (long long)r->timestamp);
}

int access_format_uchan(const uchan_record_t *r, char *buf, size_t cap) {
  return snprintf(buf, cap, "uc|%s|%s|%s|%lld\n", r->uuid, r->chan,
                  r->is_active ? "add" : "del", (long long)r->timestamp);
}

static int split_pipes(char *v, char **f, int max) {
  int n = 0;
  f[n++] = v;
  for (char *p = v; *p && n < max; p++)
    if (*p == '|') {
      *p = '\0';
      f[n++] = p + 1;
    }
  return n;
}

/* One record body (after "uf|" / "uc|"), kind 'f' or 'c' (irchub
 * hub_access_ingest). */
bool access_ingest(bot_state_t *state, char kind, const char *body, bool need_user,
                   bool *changed) {
  if (changed) *changed = false;
  char v[CFG_UC_LINE_MAX];
  if (!body || strlen(body) >= sizeof(v)) return false;
  memcpy(v, body, strlen(body) + 1);
  size_t vl = strlen(v);
  while (vl > 0 && (v[vl - 1] == '\n' || v[vl - 1] == '\r')) v[--vl] = '\0';
  char *f[6];
  int n = split_pipes(v, f, 6);
  if (need_user) {
    bool known = false;
    for (int i = 0; i < state->user_record_count && !known; i++)
      known = strcmp(state->user_records[i].uuid, f[0]) == 0;
    if (!known) return false;
  }
  bool ok;
  if (kind == 'f') {
    if (n != 3) return false;
    ok = access_uflag_put(state, f[0], f[1], (time_t)atoll(f[2]));
  } else {
    if (n != 4 || (strcmp(f[2], "add") != 0 && strcmp(f[2], "del") != 0)) return false;
    ok = access_uchan_put(state, f[0], f[1], f[2][0] == 'a', (time_t)atoll(f[3]));
  }
  if (changed) *changed = ok;
  return true;
}

/* §3.3: a live admin without uf| becomes "a", a live oper without any uc|
 * "*", stamped USER_ACCESS_MIGRATE_TS so every real record beats it (irchub
 * hub_access_migrate). */
int access_migrate(bot_state_t *state) {
  const time_t ts = USER_ACCESS_MIGRATE_TS;
  int made = 0;
  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *u = &state->user_records[i];
    if (!u->is_active) continue;
    if (u->type == 'a' && !access_uflag_find(state, u->uuid)) {
      if (access_uflag_put(state, u->uuid, "a", ts)) made++;
    } else if (u->type == 'o') {
      bool any = false;
      for (int j = 0; j < state->uchan_record_count && !any; j++)
        any = strcmp(state->uchan_records[j].uuid, u->uuid) == 0;
      if (!any && access_uchan_put(state, u->uuid, "*", true, ts)) made++;
    }
  }
  if (made)
    log_message(L_INFO, state, "[ACCESS] Migrated %d user%s to flags / channel bindings "
                "(admins: +a, opers: *)\n", made, made == 1 ? "" : "s");
  return made;
}

/* Drop records whose user is gone, and duplicates. */
void access_prune(bot_state_t *state) {
  int o = 0;
  for (int i = 0; i < state->uflag_record_count; i++) {
    bool keep = false;
    for (int u = 0; u < state->user_record_count && !keep; u++)
      keep = strcmp(state->user_records[u].uuid, state->uflag_records[i].uuid) == 0;
    for (int j = 0; j < o && keep; j++)
      keep = strcmp(state->uflag_records[j].uuid, state->uflag_records[i].uuid) != 0;
    if (keep) state->uflag_records[o++] = state->uflag_records[i];
  }
  state->uflag_record_count = o;
  o = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const uchan_record_t *r = &state->uchan_records[i];
    bool keep = false;
    for (int u = 0; u < state->user_record_count && !keep; u++)
      keep = strcmp(state->user_records[u].uuid, r->uuid) == 0;
    for (int j = 0; j < o && keep; j++)
      keep = !(strcmp(state->uchan_records[j].uuid, r->uuid) == 0 &&
               strcasecmp(state->uchan_records[j].chan, r->chan) == 0);
    if (keep) state->uchan_records[o++] = *r;
  }
  state->uchan_record_count = o;
}

/* Binding tombstones older than cutoff (0 = all); a live user's "*" del
 * stays (irchub hub_access_purge). */
int access_purge(bot_state_t *state, time_t cutoff) {
  int o = 0, dropped = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const uchan_record_t *r = &state->uchan_records[i];
    bool live_user = false;
    for (int u = 0; u < state->user_record_count && !live_user; u++)
      live_user = state->user_records[u].is_active &&
                  strcmp(state->user_records[u].uuid, r->uuid) == 0;
    if (!r->is_active && (cutoff == 0 || r->timestamp < cutoff) &&
        !(live_user && strcmp(r->chan, "*") == 0)) {
      dropped++;
      continue;
    }
    /* a live binding to a channel no one manages is an orphan (irchub) */
    if (r->is_active && strcmp(r->chan, "*") != 0) {
      const chan_t *c = channel_find(state, r->chan);
      if (!c || !c->is_managed) {
        dropped++;
        continue;
      }
    }
    state->uchan_records[o++] = *r;
  }
  state->uchan_record_count = o;
  access_prune(state);
  return dropped;
}

/* "*" when global, else the live channels comma-joined ("" for none). */
void access_user_chans(const bot_state_t *state, const char *uuid, char *out, size_t cap) {
  if (!cap) return;
  out[0] = '\0';
  bool global = false;
  access_user_chan_count(state, uuid, &global);
  if (global) {
    snprintf(out, cap, "*");
    return;
  }
  size_t o = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    int w = snprintf(out + o, cap - o, "%s%s", o ? "," : "", r->chan);
    if (w < 0 || (size_t)w >= cap - o) {
      out[o] = '\0';
      return;
    }
    o += (size_t)w;
  }
}

time_t access_next_ts(bot_state_t *state, const char *uuid) {
  time_t prev = 0;
  uflag_record_t *f = access_uflag_find(state, uuid);
  if (f) prev = f->timestamp;
  for (int i = 0; i < state->uchan_record_count; i++)
    if (strcmp(state->uchan_records[i].uuid, uuid) == 0 && state->uchan_records[i].timestamp > prev)
      prev = state->uchan_records[i].timestamp;
  return lww_next_ts(prev);
}

/* An oper binding change the U10 way (irchub hub_access_chan_change).  The
 * number of records written, -1 when the table is full. */
int access_chan_change(bot_state_t *state, const char *uuid, bool add, const char *chan) {
  time_t ts = access_next_ts(state, uuid);
  bool star = strcmp(chan, "*") == 0;
  int n = 0;
#define UC_PUT(c_, act_)                                                \
  do {                                                                  \
    if (!access_uchan_put(state, uuid, (c_), (act_), ts)) return -1;    \
    n++;                                                                \
  } while (0)
  if (add) {
    UC_PUT(chan, true);
    for (int i = 0; i < state->uchan_record_count; i++) {
      uchan_record_t *r = &state->uchan_records[i];
      if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
      bool r_star = strcmp(r->chan, "*") == 0;
      if (star ? !r_star : r_star) {
        char c[MAX_CHAN];
        snprintf(c, sizeof(c), "%s", r->chan);
        UC_PUT(c, false);
      }
    }
    if (!star && !access_uchan_find(state, uuid, "*")) UC_PUT("*", false);
  } else if (star) {
    for (int i = 0; i < state->uchan_record_count; i++) {
      uchan_record_t *r = &state->uchan_records[i];
      if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
      char c[MAX_CHAN];
      snprintf(c, sizeof(c), "%s", r->chan);
      UC_PUT(c, false);
    }
    if (!access_uchan_find(state, uuid, "*")) UC_PUT("*", false);
  } else {
    UC_PUT(chan, false);
  }
#undef UC_PUT
  return n;
}

/* A channel removed takes its oper bindings with it, at the c| del stamp
 * (plan U6; irchub hub_chan_cascade_del).  "*" stays.  How many it removed. */
int access_chan_cascade(bot_state_t *state, const char *chan, time_t ts) {
  int n = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->chan, "*") == 0 || strcasecmp(r->chan, chan) != 0) continue;
    if (access_uchan_put(state, r->uuid, r->chan, false, ts)) n++;
  }
  return n;
}
