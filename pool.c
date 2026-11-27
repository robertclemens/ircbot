/* pool.c — the bot side of the hub's IRC server pool (2.5.4).
 *
 * Plan: irchub/docs/plans/2026-10-29_server_pool_plan.md §5.  A hub-managed
 * bot (hub_count > 0) dials only from the pool the hub sends (N|/S| lines,
 * cached in the .cnf); its local s| lines are dormant.  A standalone bot dials
 * its local s| list.  Either way irc_connect works over server_list[], which
 * servers_rebuild() fills from the right source. */
#include "bot.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---- records ---------------------------------------------------------- */

static pool_entry_t *pool_find(bot_state_t *state, const char *uuid) {
  for (int i = 0; i < state->pool_count; i++)
    if (strcmp(state->pool[i].s.uuid, uuid) == 0) return &state->pool[i];
  return NULL;
}

void pool_clear(bot_state_t *state) {
  state->pool_count = 0;
  memset(&state->pool_net, 0, sizeof(state->pool_net));
  state->pool_net_ts = 0;
  state->pool_known = false;
}

/* "<value>|<ts>": the value and the stamp; false without a stamp. */
static bool split_ts(const char *data, char *value, size_t cap, time_t *ts) {
  const char *bar = strrchr(data, '|');
  if (!bar) return false;
  size_t n = (size_t)(bar - data);
  if (n >= cap) return false;
  char *end = NULL;
  long long v = strtoll(bar + 1, &end, 10);
  if (!end || *end || end == bar + 1 || v < 0) return false;
  memcpy(value, data, n);
  value[n] = '\0';
  *ts = (time_t)v;
  return true;
}

bool pool_ingest_line(bot_state_t *state, char tag, const char *data) {
  static char value[POOL_R_LINE_MAX]; /* the longest of N|/S|/R| */
  time_t ts;
  if (!split_ts(data, value, sizeof(value), &ts)) return false;
  if (tag == 'R') {
    /* The hubs' server order for this bot: computed, so no stamp to compare;
     * the newest one wins (pool_clear leaves it: an order outlives a pool
     * refresh that does not carry one). */
    static pool_order_t o;
    if (!pool_order_parse(value, &o)) return false;
    state->pool_order = o;
    state->pool_order_known = true;
    return true;
  }
  if (tag == 'N') {
    pool_net_t n;
    if (!pool_net_parse(value, &n)) return false;
    if (strcmp(n.net_id, POOL_DEFAULT_NET) != 0) return true; /* v1: one network */
    if (state->pool_known && ts < state->pool_net_ts) return true;
    state->pool_net = n;
    state->pool_net_ts = ts;
    state->pool_known = true;
    return true;
  }
  if (tag != 'S') return false;
  pool_srv_t s;
  if (!pool_srv_parse(value, &s)) return false;
  pool_entry_t *e = pool_find(state, s.uuid);
  if (e) {
    if (ts < e->ts) return true;
  } else {
    if (state->pool_count >= MAX_POOL_SERVERS + MAX_POOL_TOMBS) return false;
    e = &state->pool[state->pool_count++];
  }
  e->s = s;
  e->ts = ts;
  return true;
}

int pool_format_lines(const bot_state_t *state, char *buf, size_t cap) {
  size_t off = 0;
  char v[POOL_N_LINE_MAX > POOL_S_LINE_MAX ? POOL_N_LINE_MAX : POOL_S_LINE_MAX];
  if (state->pool_known) {
    if (pool_net_format(&state->pool_net, v, sizeof(v)) < 0) return -1;
    int w = snprintf(buf + off, cap - off, "N|%s|%lld\n", v, (long long)state->pool_net_ts);
    if (w < 0 || (size_t)w >= cap - off) return -1;
    off += (size_t)w;
  }
  for (int i = 0; i < state->pool_count; i++) {
    if (pool_srv_format(&state->pool[i].s, v, sizeof(v)) < 0) return -1;
    int w = snprintf(buf + off, cap - off, "S|%s|%lld\n", v, (long long)state->pool[i].ts);
    if (w < 0 || (size_t)w >= cap - off) return -1;
    off += (size_t)w;
  }
  if (state->pool_order_known) {
    static char ov[POOL_R_LINE_MAX];
    pool_order_t o = state->pool_order;
    if (pool_order_format(&o, ov, sizeof(ov)) < 0) return -1;
    int w = snprintf(buf + off, cap - off, "R|%s|0\n", ov);
    if (w < 0 || (size_t)w >= cap - off) return -1;
    off += (size_t)w;
  }
  return (int)off;
}

static bool entry_eligible(const pool_entry_t *e) {
  return !e->s.deleted && e->s.state == POOL_OK &&
         strcmp(e->s.net_id, POOL_DEFAULT_NET) == 0;
}

int pool_eligible_count(const bot_state_t *state) {
  int n = 0;
  for (int i = 0; i < state->pool_count; i++) n += entry_eligible(&state->pool[i]);
  return n;
}

/* ---- dial list ---------------------------------------------------------- */

/* The dial string of an entry: always "host:port" (every entry has one). */
static void entry_dial(const pool_srv_t *s, char *out, size_t cap) {
  snprintf(out, cap, "%s:%d", s->host, s->port);
}

/* Rendezvous score of (this bot, entry): with no R| order from the hubs,
 * every bot orders the pool its own way, so bots still spread out. */
static uint64_t hrw(const char *bot_uuid, const char *entry_uuid) {
  char in[160];
  int n = snprintf(in, sizeof(in), "%s|%s", bot_uuid, entry_uuid);
  unsigned char h[EVP_MAX_MD_SIZE];
  unsigned int hl = 0;
  if (n < 0 || !EVP_Digest(in, (size_t)n, h, &hl, EVP_sha256(), NULL) || hl < 8) return 0;
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | h[i];
  return v;
}

typedef struct {
  const pool_entry_t *e;
  uint64_t score;
} ranked_t;

static int ranked_cmp(const void *a, const void *b) {
  const ranked_t *x = a, *y = b;
  if (x->score != y->score) return x->score > y->score ? -1 : 1;
  return strcmp(x->e->s.uuid, y->e->s.uuid);
}

/* Eligible entries in this bot's dial order: the hubs' R| order first (a
 * higher score for an earlier place), then any entry the order does not name
 * yet (a server added since) in HRW order behind it. */
static int pool_ranked(const bot_state_t *state, ranked_t *out, int max) {
  int n = 0;
  for (int i = 0; i < state->pool_count && n < max; i++) {
    const pool_entry_t *e = &state->pool[i];
    if (!entry_eligible(e)) continue;
    out[n].e = e;
    int at = -1;
    for (int k = 0; state->pool_order_known && k < state->pool_order.n && at < 0; k++)
      if (strcmp(state->pool_order.ids[k], e->s.uuid) == 0) at = k;
    out[n].score = at >= 0 ? UINT64_MAX - (uint64_t)at : hrw(state->bot_uuid, e->s.uuid) >> 1;
    n++;
  }
  qsort(out, (size_t)n, sizeof(out[0]), ranked_cmp);
  return n;
}

static void link_send(bot_state_t *state);

static int dial_count(char *const *list, int n, const char *dial) {
  int c = 0;
  for (int i = 0; i < n; i++)
    if (list[i] && strcasecmp(list[i], dial) == 0) c++;
  return c;
}

/* Slot identity across rebuilds: two pool slots by uuid, two local slots by
 * dial string.  A local slot and a pool slot (the hub's first pool landing
 * while the bot is on, or dialing, a local s| server) are the same server
 * only when their host:port is identical and names exactly one slot on each
 * side; anything else is no match, never a guess. */
static bool slot_same(const char *uuid_a, const char *dial_a, char *const *list_a, int n_a,
                      const char *uuid_b, const char *dial_b, char *const *list_b,
                      int n_b) {
  if (!dial_a || !dial_b) return false;
  if (uuid_a[0] && uuid_b[0]) return strcmp(uuid_a, uuid_b) == 0;
  if (strcasecmp(dial_a, dial_b) != 0) return false;
  if (!uuid_a[0] && !uuid_b[0]) return true;
  return dial_count(list_a, n_a, dial_a) == 1 && dial_count(list_b, n_b, dial_b) == 1;
}

/* A 2.5.3 bot's first start on 2.5.4 (and any hub-managed bot that has never
 * held a pool entry): it dials its own s| list until a hub sends S| lines,
 * so a hub it cannot reach never keeps it off IRC.  Any S| at all, a
 * tombstone included (an admin's server del ... force), ends it for good.
 * Legacy: 2.5.5 drops it with the s| purge. */
bool pool_local_fallback(const bot_state_t *state) {
  return state->hub_count > 0 && state->pool_count == 0 && state->local_server_count > 0;
}

void servers_rebuild(bot_state_t *state) {
  /* Old slots, to carry holds and the live link over. */
  static char old_uuid[MAX_SERVERS][POOL_UUID_LEN + 1];
  static server_block_t old_block[MAX_SERVERS];
  char *old_dial[MAX_SERVERS];
  int old_n = state->server_count;
  for (int i = 0; i < old_n; i++) {
    old_dial[i] = state->server_list[i];
    memcpy(old_uuid[i], state->dial_uuid[i], sizeof(old_uuid[i]));
    old_block[i] = state->server_blocks[i];
  }
  /* The live link's slot: registered, or still dialing / registering (an R|
   * order can land then, and the slot must survive it). */
  int live_old = ((state->status & S_CONNECTED) || state->server_fd >= 0) ? state->irc_server_idx : -1;
  /* A pending `jump <server>` names a slot: follow its server, not its index. */
  int jump_old = state->jump_slot1 - 1;
  if (jump_old >= old_n) jump_old = -1;

  int n = 0;
  bool local = pool_local_fallback(state);
  if (local != state->pool_using_local) {
    if (local)
      log_message(L_INFO, state,
                  "[POOL] No server pool from a hub yet: dialing the %d local server%s (s|) "
                  "until one arrives\n",
                  state->local_server_count, state->local_server_count == 1 ? "" : "s");
    else if (state->hub_count > 0)
      log_message(L_INFO, state,
                  "[POOL] Server pool received from the hub: dialing it, local s| now dormant\n");
    state->pool_using_local = local;
  }
  if (state->hub_count > 0 && !local) {
    static ranked_t r[MAX_POOL_SERVERS + MAX_POOL_TOMBS];
    int rn = pool_ranked(state, r, MAX_POOL_SERVERS + MAX_POOL_TOMBS);
    for (int i = 0; i < rn && n < MAX_SERVERS; i++) {
      char dial[POOL_HOST_MAX + 8];
      entry_dial(&r[i].e->s, dial, sizeof(dial));
      char *d = strdup(dial);
      if (!d) break;
      state->server_list[n] = d;
      memcpy(state->dial_uuid[n], r[i].e->s.uuid, sizeof(state->dial_uuid[n]));
      n++;
    }
  } else {
    for (int i = 0; i < state->local_server_count && n < MAX_SERVERS; i++) {
      char *d = strdup(state->local_servers[i]);
      if (!d) break;
      state->server_list[n] = d;
      state->dial_uuid[n][0] = '\0';
      n++;
    }
  }
  state->server_list[n] = NULL;
  state->server_count = n;

  int live_new = -1, jump_new = -1;
  for (int i = 0; i < n; i++) {
    memset(&state->server_blocks[i], 0, sizeof(server_block_t));
    for (int j = 0; j < old_n; j++) {
      if (!slot_same(state->dial_uuid[i], state->server_list[i], state->server_list, n,
                     old_uuid[j], old_dial[j], old_dial, old_n))
        continue;
      state->server_blocks[i] = old_block[j];
      if (j == live_old) live_new = i;
      if (j == jump_old) jump_new = i;
      break;
    }
  }
  for (int i = n; i < MAX_SERVERS; i++) memset(&state->server_blocks[i], 0, sizeof(server_block_t));
  for (int j = 0; j < old_n; j++) free(old_dial[j]);

  /* A connected bot stays connected (plan D13); a link whose entry is gone
   * just has no slot for a refusal to land on. */
  state->irc_server_idx = live_new;
  state->current_server_index = live_new >= 0 ? live_new + 1 : 0;
  state->jump_slot1 = jump_new + 1; /* 0 when its server is gone */
  /* A local slot matched to its pool entry: the hub learns which entry the
   * link is on (it was told "-" at the dial). */
  if (live_new >= 0 && state->dial_uuid[live_new][0] &&
      strcmp(state->irc_link_entry, state->dial_uuid[live_new]) != 0) {
    snprintf(state->irc_link_entry, sizeof(state->irc_link_entry), "%s",
             state->dial_uuid[live_new]);
    link_send(state);
  }

  bool idle = state->hub_count > 0 && n == 0;
  if (idle && !state->pool_idle) {
    state->pool_idle_warned = 0;
    if (!(state->status & S_CONNECTED)) {
      log_message(L_INFO, state,
                  state->pool_known
                      ? "[POOL] Network %s: no usable server, waiting for one\n"
                      : "[POOL] Waiting for the hub's server pool before connecting to IRC\n",
                  POOL_DEFAULT_NET);
      state->pool_idle_warned = time(NULL);
    }
  } else if (!idle && state->pool_idle) {
    log_message(L_INFO, state, "[POOL] Network %s: %d usable server%s again\n",
                POOL_DEFAULT_NET, n, n == 1 ? "" : "s");
  }
  state->pool_idle = idle;
  if (idle && !(state->status & S_CONNECTED)) pool_link_note(state, "idle", "");
}

const pool_entry_t *pool_entry_of_slot(const bot_state_t *state, int slot) {
  if (slot < 0 || slot >= state->server_count || !state->dial_uuid[slot][0]) return NULL;
  for (int i = 0; i < state->pool_count; i++)
    if (strcmp(state->pool[i].s.uuid, state->dial_uuid[slot]) == 0) return &state->pool[i];
  return NULL;
}

int pool_unlisted(const bot_state_t *state, const pool_entry_t **out, int max) {
  int n = 0;
  for (int i = 0; i < state->pool_count && n < max; i++) {
    const pool_entry_t *e = &state->pool[i];
    if (e->s.deleted || entry_eligible(e)) continue;
    out[n++] = e;
  }
  return n;
}

/* ---- migration and going hubless ------------------------------------- */

void pool_after_hub_config(bot_state_t *state) {
  /* pool_hub_seen, not pool_known: the cached pool proves nothing about this
   * link, and a 2.5.3 hub would read an S| push as a phantom bot. */
  if (!state->pool_hub_seen || state->pool_migrated || !state->hub_authenticated) return;
  state->pool_migrated = true;
  if (state->local_server_count == 0) {
    config_write_local_with_state_pass(state);
    return;
  }
  /* Every local s| as an S| add stamped 0: it loses to anything a hub holds,
   * a deleted server above all (plan D15); the hub stamps an unknown one.
   * Offered under opt 'h' too: the hub takes a bot's migration once, for
   * POOL_MIGRATE_WINDOW (irchub hub.h), so an opt-h net does not roll onto an
   * empty pool.  The local s| lines stay (dormant) for a 2.5.3 failback;
   * 2.5.5 purges them and ends the opt 'h' exception. */
  static char lines[MAX_SERVERS * POOL_S_LINE_MAX];
  size_t off = 0;
  int sent = 0;
  for (int i = 0; i < state->local_server_count; i++) {
    pool_srv_t s;
    memset(&s, 0, sizeof(s));
    if (!pool_hostport_parse(state->local_servers[i], s.host, sizeof(s.host), &s.port) ||
        !pool_srv_uuid(POOL_DEFAULT_NET, s.host, s.port, s.uuid)) {
      log_message(L_INFO, state, "[POOL] Local server '%s' is not a valid host[:port]; not migrated\n",
                  state->local_servers[i]);
      continue;
    }
    snprintf(s.net_id, sizeof(s.net_id), "%s", POOL_DEFAULT_NET);
    s.weight = 1;
    s.state = POOL_OK;
    char v[POOL_S_LINE_MAX];
    if (pool_srv_format(&s, v, sizeof(v)) < 0) continue;
    int w = snprintf(lines + off, sizeof(lines) - off, "S|%s|0\n", v);
    if (w < 0 || (size_t)w >= sizeof(lines) - off) break;
    off += (size_t)w;
    sent++;
  }
  /* In frames of at most POOL_PUSH_CHUNK, split at line boundaries: the hub
   * reads one push into a MAX_BUFFER work buffer, and nothing may be cut. */
  for (size_t at = 0; at < off;) {
    size_t n = off - at;
    if (n > POOL_PUSH_CHUNK) {
      n = POOL_PUSH_CHUNK;
      while (n > 0 && lines[at + n - 1] != '\n') n--;
    }
    if (n == 0 || !hub_client_push_lines(state, lines + at, n)) {
      state->pool_migrated = false; /* the next config tries again */
      return;
    }
    at += n;
  }
  log_message(L_INFO, state, "[POOL] Offered %d local server%s to the hub's pool\n", sent,
              sent == 1 ? "" : "s");
  config_write_local_with_state_pass(state);
}

void pool_go_hubless(bot_state_t *state) {
  static ranked_t r[MAX_POOL_SERVERS + MAX_POOL_TOMBS];
  int rn = pool_ranked(state, r, MAX_POOL_SERVERS + MAX_POOL_TOMBS);
  if (state->pool_count == 0) {
    /* Never got a pool (an emptied one keeps its tombstones): the local list
     * is all it has. */
    state->pool_migrated = false;
    servers_rebuild(state);
    return;
  }
  for (int i = 0; i < state->local_server_count; i++) free(state->local_servers[i]);
  state->local_server_count = 0;
  /* The server it is on first, then this bot's HRW order. */
  const char *live = (state->status & S_CONNECTED) && state->irc_server_idx >= 0 &&
                             state->irc_server_idx < state->server_count
                         ? state->dial_uuid[state->irc_server_idx]
                         : "";
  for (int pass = 0; pass < 2; pass++)
    for (int i = 0; i < rn && state->local_server_count < MAX_SERVERS; i++) {
      bool is_live = live[0] && strcmp(r[i].e->s.uuid, live) == 0;
      if ((pass == 0) != is_live) continue;
      char dial[POOL_HOST_MAX + 8];
      entry_dial(&r[i].e->s, dial, sizeof(dial));
      char *d = strdup(dial);
      if (!d) break;
      state->local_servers[state->local_server_count++] = d;
    }
  state->local_servers[state->local_server_count] = NULL;
  /* The pool is the hub's; without one it has nothing to keep it current.
   * N| stays: it is the network check standalone too. */
  state->pool_count = 0;
  state->pool_migrated = false;
  log_message(L_INFO, state, "[POOL] Hubless: pool -> %d local server%s\n",
              state->local_server_count, state->local_server_count == 1 ? "" : "s");
  servers_rebuild(state);
}

/* ---- +server / -server ------------------------------------------------ */

static bool local_find(const bot_state_t *state, const char *hostport) {
  for (int i = 0; i < state->local_server_count; i++)
    if (strcasecmp(state->local_servers[i], hostport) == 0) return true;
  return false;
}

/* A pool push from this bot: refused under opt h (the hub refuses it too). */
static bool pool_push_ok(const bot_state_t *state, char *err, size_t errcap) {
  if (is_opt_set(state, OPT_HUB_ONLY_MUTATIONS)) {
    snprintf(err, errcap, "the server pool is managed on the hub (opt h); use the hub "
                          "console 'server add/del'");
    return false;
  }
  if (!state->pool_hub_seen || !state->hub_authenticated) {
    snprintf(err, errcap, "no hub link with a server pool yet");
    return false;
  }
  return true;
}

static bool push_entry(bot_state_t *state, const pool_entry_t *e) {
  char v[POOL_S_LINE_MAX], line[POOL_S_LINE_MAX + 32];
  if (pool_srv_format(&e->s, v, sizeof(v)) < 0) return false;
  int w = snprintf(line, sizeof(line), "S|%s|%lld\n", v, (long long)e->ts);
  return w > 0 && (size_t)w < sizeof(line) && hub_client_push_lines(state, line, (size_t)w);
}

bool servers_add(bot_state_t *state, const char *hostport, char *err, size_t errcap) {
  pool_srv_t s;
  memset(&s, 0, sizeof(s));
  if (!pool_hostport_parse(hostport, s.host, sizeof(s.host), &s.port)) {
    snprintf(err, errcap, "'%s' is not host[:port]", hostport);
    return false;
  }
  if (state->hub_count == 0) {
    if (local_find(state, hostport)) {
      snprintf(err, errcap, "'%s' is already listed", hostport);
      return false;
    }
    if (state->local_server_count >= MAX_SERVERS) {
      snprintf(err, errcap, "the server list is full (%d)", MAX_SERVERS);
      return false;
    }
    char *d = strdup(hostport);
    if (!d) { snprintf(err, errcap, "out of memory"); return false; }
    state->local_servers[state->local_server_count++] = d;
    state->local_servers[state->local_server_count] = NULL;
    servers_rebuild(state);
    config_write_with_state_pass(state);
    return true;
  }
  if (!pool_push_ok(state, err, errcap)) return false;
  snprintf(s.net_id, sizeof(s.net_id), "%s", POOL_DEFAULT_NET);
  if (!pool_srv_uuid(s.net_id, s.host, s.port, s.uuid)) {
    snprintf(err, errcap, "'%s' is not host[:port]", hostport);
    return false;
  }
  pool_entry_t *e = pool_find(state, s.uuid);
  if (e && !e->s.deleted) {
    snprintf(err, errcap, "'%s' is already in the pool", hostport);
    return false;
  }
  if (!e && state->pool_count >= MAX_POOL_SERVERS + MAX_POOL_TOMBS) {
    snprintf(err, errcap, "the pool is full");
    return false;
  }
  /* From the entry it revives, or all zero: never stack garbage. */
  pool_entry_t next = e ? *e : (pool_entry_t){0};
  next.s = s;
  next.s.weight = e ? e->s.weight : 1;
  next.s.max = e ? e->s.max : 0;
  next.s.state = POOL_OK;
  next.s.deleted = false;
  next.ts = lww_next_ts(e ? e->ts : 0);
  if (!push_entry(state, &next)) {
    snprintf(err, errcap, "could not send it to the hub");
    return false;
  }
  if (!e) e = &state->pool[state->pool_count++];
  *e = next;
  servers_rebuild(state);
  config_write_local_with_state_pass(state);
  return true;
}

bool servers_del(bot_state_t *state, const char *what, char *err, size_t errcap) {
  if (state->hub_count == 0) {
    for (int i = 0; i < state->local_server_count; i++) {
      if (strcasecmp(state->local_servers[i], what) != 0) continue;
      free(state->local_servers[i]);
      for (int j = i; j < state->local_server_count - 1; j++)
        state->local_servers[j] = state->local_servers[j + 1];
      state->local_servers[--state->local_server_count] = NULL;
      servers_rebuild(state);
      config_write_with_state_pass(state);
      return true;
    }
    snprintf(err, errcap, "server '%s' not found", what);
    return false;
  }
  if (!pool_push_ok(state, err, errcap)) return false;
  pool_entry_t *e = NULL;
  if (strlen(what) == POOL_UUID_LEN) e = pool_find(state, what);
  if (!e) {
    pool_srv_t s;
    if (pool_hostport_parse(what, s.host, sizeof(s.host), &s.port) &&
        pool_srv_uuid(POOL_DEFAULT_NET, s.host, s.port, s.uuid))
      e = pool_find(state, s.uuid);
  }
  if (!e || e->s.deleted) {
    snprintf(err, errcap, "server '%s' is not in the pool", what);
    return false;
  }
  if (entry_eligible(e) && pool_eligible_count(state) <= 1) {
    snprintf(err, errcap,
             "%s is the last usable server of network %s -- removing it could take all "
             "bots off IRC; add another first, or use the hub console 'server del %s force'",
             e->s.host, POOL_DEFAULT_NET, e->s.host);
    return false;
  }
  pool_entry_t next = *e;
  next.s.deleted = true;
  next.ts = lww_next_ts(e->ts);
  if (!push_entry(state, &next)) {
    snprintf(err, errcap, "could not send it to the hub");
    return false;
  }
  *e = next;
  servers_rebuild(state);
  config_write_local_with_state_pass(state);
  return true;
}

void pool_changed(bot_state_t *state) {
  /* A new N| or a cleared entry may make a wrong-network server right: the
   * next connect checks it again. */
  for (int i = 0; i < state->server_count; i++)
    if (state->server_blocks[i].kind == SB_WRONG_NET)
      memset(&state->server_blocks[i], 0, sizeof(server_block_t));
  servers_rebuild(state);
}

/* ---- the NETWORK= check (plan §5.4) ----------------------------------- */

void netcheck_arm(bot_state_t *state) {
  state->net_check = 1;
  state->net_check_deadline = time(NULL) + NETCHECK_WAIT;
}

bool netcheck_passed(const bot_state_t *state) { return state->net_check == 2; }

static void netcheck_report(bot_state_t *state, const char *kind) {
  const pool_entry_t *e = pool_entry_of_slot(state, state->irc_server_idx);
  if (!e) return; /* a local server or a jump: no pool entry to report on */
  char payload[POOL_UUID_LEN + POOL_NET_NAME_MAX + 300];
  snprintf(payload, sizeof(payload), "%s|%s|%s|%.255s", e->s.uuid, kind, state->isup.network,
           state->actual_server_name);
  hub_client_send_server_report(state, payload);
}

static void netcheck_hold(bot_state_t *state);

/* ---- the link proof ------------------------------------------------------
 * The server says another NETWORK=, but it may be ours misconfigured.  Ask
 * the server which trusted bots it can see (ISON); up to NETPROOF_PEERS of
 * them get a sealed ~B2 NETPROBE <nonce> over IRC.  A peer on a verified
 * server WHOISes us and answers NETPROBE-OK <nonce> <server it sees us on>:
 * our own server name there proves the two servers are one network (a relay
 * bridge can forward messages, but our client is in no WHOIS on a network it
 * is not on).  Proven: used for this connection, reported "linked"; never
 * persisted.  Not within NETPROOF_WAIT: the hold, as before. */
static bool netproof_start(bot_state_t *state) {
  if (state->hub_count == 0 || state->trusted_bot_count == 0) return false;
  unsigned char rnd[NETPROOF_NONCE_HEX / 2];
  if (RAND_bytes(rnd, sizeof(rnd)) != 1) return false;
  for (size_t i = 0; i < sizeof(rnd); i++)
    snprintf(state->netproof_nonce + 2 * i, 3, "%02x", rnd[i]);
  char line[400] = "ISON";
  size_t len = 4;
  for (int i = 0; i < state->trusted_bot_count; i++) {
    char nick[MAX_NICK];
    auth_trusted_bot_nick(&state->trusted_bots[i], nick);
    size_t nl = strlen(nick);
    if (!nl || len + 1 + nl >= sizeof(line)) continue;
    line[len++] = ' ';
    memcpy(line + len, nick, nl + 1);
    len += nl;
  }
  if (len == 4) return false;
  state->net_check = 3;
  state->netproof_deadline = time(NULL) + NETPROOF_WAIT;
  log_message(L_INFO, state, "[POOL] %s says NETWORK=%s, expected %s: proving the link "
              "through other bots\n", state->actual_server_name[0] ? state->actual_server_name : "server",
              state->isup.network, state->pool_net.name);
  irc_printf(state, "%s\r\n", line);
  return true;
}

/* 303 RPL_ISON while proving: the trusted bots this server sees. */
void netproof_ison(bot_state_t *state, char *nicks) {
  if (state->net_check != 3 || !nicks) return;
  char *sp = NULL;
  int sent = 0;
  for (char *n = strtok_r(nicks, " :", &sp); n && sent < NETPROOF_PEERS;
       n = strtok_r(NULL, " :", &sp)) {
    if (irc_casecmp(n, state->current_nick) == 0) continue;
    bot_comms_send_command_irc(state, n, "NETPROBE %s", state->netproof_nonce);
    sent++;
  }
  if (!sent)
    log_message(L_INFO, state, "[POOL] No trusted bot is visible from %s to prove it\n",
                state->actual_server_name);
}

/* Our own server's NETWORK= is the pool's (not merely proven linked: a
 * proof never vouches for another). */
static bool netcheck_ok_here(const bot_state_t *state) {
  return state->isup.network[0] && state->pool_known &&
         pool_net_matches(&state->pool_net, state->isup.network);
}

static bool nonce_ok(const char *s) {
  if (!s || strlen(s) != NETPROOF_NONCE_HEX) return false;
  for (const char *p = s; *p; p++)
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
  return true;
}

/* A peer asks (over IRC, sealed): WHOIS it, if our own server is verified. */
void netproof_probe(bot_state_t *state, const char *from_nick, const char *nonce) {
  if (!from_nick || !nonce_ok(nonce) || state->net_check != 2 || !netcheck_ok_here(state))
    return;
  time_t now = time(NULL);
  int slot = -1;
  for (int i = 0; i < NETPROOF_PEND; i++) {
    if (state->netprobe_pend[i].until && now > state->netprobe_pend[i].until)
      memset(&state->netprobe_pend[i], 0, sizeof(state->netprobe_pend[i]));
    if (!state->netprobe_pend[i].until && slot < 0) slot = i;
  }
  if (slot < 0) return; /* busy: the prober asks others too */
  snprintf(state->netprobe_pend[slot].nonce, sizeof(state->netprobe_pend[slot].nonce), "%s",
           nonce);
  snprintf(state->netprobe_pend[slot].prober, sizeof(state->netprobe_pend[slot].prober), "%s",
           from_nick);
  state->netprobe_pend[slot].until = now + NETPROOF_WAIT;
  irc_printf(state, "WHOIS %s\r\n", from_nick);
}

/* 312 RPL_WHOISSERVER: answer a pending probe with the server we see. */
void netproof_whois_server(bot_state_t *state, const char *nick, const char *server) {
  if (!nick || !server) return;
  for (int i = 0; i < NETPROOF_PEND; i++) {
    if (!state->netprobe_pend[i].until ||
        irc_casecmp(state->netprobe_pend[i].prober, nick) != 0)
      continue;
    bot_comms_send_command_irc(state, nick, "NETPROBE-OK %s %s", state->netprobe_pend[i].nonce,
                               server);
    memset(&state->netprobe_pend[i], 0, sizeof(state->netprobe_pend[i]));
  }
}

/* A peer's answer: our own server, seen from a verified one, is the proof. */
void netproof_ok(bot_state_t *state, const char *nonce, const char *server, const char *by) {
  if (state->net_check != 3 || !nonce_ok(nonce) || strcmp(nonce, state->netproof_nonce) != 0)
    return;
  if (!server || strcasecmp(server, state->actual_server_name) != 0) {
    log_message(L_INFO, state, "[POOL] %s sees me on %s, not %s: no proof\n", by,
                server ? server : "?", state->actual_server_name);
    return;
  }
  state->net_check = 2;
  state->netproof_nonce[0] = '\0';
  log_message(L_INFO, state, "[POOL] %s says NETWORK=%s; linked to %s (proven by %s): using it\n",
              state->actual_server_name, state->isup.network, state->pool_net.name, by);
  netcheck_report(state, "linked");
}

static void netcheck_decide(bot_state_t *state) {
  const char *net = state->isup.network;
  const bool learned = state->pool_known && state->pool_net.name[0];
  if (!learned || (net[0] && pool_net_matches(&state->pool_net, net))) {
    state->net_check = 2;
    if (!learned && net[0] && state->hub_count == 0) {
      /* Standalone: learn the network locally, then lock it (plan D6). */
      memset(&state->pool_net, 0, sizeof(state->pool_net));
      snprintf(state->pool_net.net_id, sizeof(state->pool_net.net_id), "%s", POOL_DEFAULT_NET);
      snprintf(state->pool_net.label, sizeof(state->pool_net.label), "%s", POOL_DEFAULT_NET);
      snprintf(state->pool_net.name, sizeof(state->pool_net.name), "%s", net);
      state->pool_net.pace_gap = POOL_PACE_GAP_DEFAULT;
      state->pool_net_ts = time(NULL);
      state->pool_known = true;
      log_message(L_INFO, state, "[POOL] Network learned: %s\n", net);
      config_write_local_with_state_pass(state);
    }
    /* ok, with the name the hub learns it from; no token while nothing is
     * learned is fine and says nothing (the hub would count "unverified" as
     * a strike against the entry). */
    if (net[0]) netcheck_report(state, "ok");
    return;
  }
  /* The wrong network, or none named once one is known: prove the link
   * first when trusted bots can vouch for it, else off at once. */
  if (net[0] && netproof_start(state)) return;
  netcheck_hold(state);
}

/* Off this server for WRONGNET_HOLD: its NETWORK= is not ours, unproven. */
static void netcheck_hold(bot_state_t *state) {
  const char *net = state->isup.network;
  int idx = state->irc_server_idx;
  log_message(L_INFO, state, "[POOL] %s says NETWORK=%s, expected %s: wrong network, "
              "disconnecting\n", state->actual_server_name[0] ? state->actual_server_name : "server",
              net[0] ? net : "(none)", state->pool_net.name);
  netcheck_report(state, net[0] ? "wrongnet" : "unverified");
  if (idx >= 0 && idx < state->server_count) {
    server_block_t *b = &state->server_blocks[idx];
    b->kind = SB_WRONG_NET;
    b->until = time(NULL) + WRONGNET_HOLD;
    snprintf(b->reason, sizeof(b->reason), "%s", net[0] ? net : "(no NETWORK=)");
  }
  irc_printf(state, "QUIT :wrong network\r\n");
  irc_disconnect(state);
}

void netcheck_end_of_motd(bot_state_t *state) {
  if (state->net_check == 1) netcheck_decide(state);
}

void netcheck_tick(bot_state_t *state) {
  if (state->net_check == 1 && time(NULL) >= state->net_check_deadline) netcheck_decide(state);
  if (state->net_check == 3 && time(NULL) >= state->netproof_deadline) {
    log_message(L_INFO, state, "[POOL] No trusted bot proved %s linked within %d s\n",
                state->actual_server_name, NETPROOF_WAIT);
    state->netproof_nonce[0] = '\0';
    netcheck_hold(state);
  }
}

/* ---- the IRC link state to the hub (CMD_BOT_IRC_LINK) ------------------ */

static void link_send(bot_state_t *state) {
  if (!state->irc_link[0]) return;
  char payload[sizeof(((bot_state_t *)0)->irc_link_sent)];
  /* 4th field: the server's 005 NETWORK= (bot show), "-" until it is in;
   * a hub reading three fields stops before it. */
  snprintf(payload, sizeof(payload), "%s|%s|%s|%s", POOL_DEFAULT_NET,
           state->irc_link_entry[0] ? state->irc_link_entry : "-", state->irc_link,
           state->isup.network[0] ? state->isup.network : "-");
  if (strcmp(payload, state->irc_link_sent) == 0) return;
  if (hub_client_send_irc_link(state, payload))
    snprintf(state->irc_link_sent, sizeof(state->irc_link_sent), "%s", payload);
}

void pool_link_note(bot_state_t *state, const char *link, const char *entry) {
  snprintf(state->irc_link, sizeof(state->irc_link), "%s", link);
  if (entry) snprintf(state->irc_link_entry, sizeof(state->irc_link_entry), "%s", entry);
  link_send(state);
}

void pool_link_resend(bot_state_t *state) { link_send(state); }

/* ---- the pick: the order, held slots out, the pace gap ------------------ */

/* The first slot to dial: slots are in dial order (servers_rebuild).  A slot
 * held by a ban or throttle is out; one dialed less than the R| pace gap ago
 * is out too (soonest says when it is back); one whose last attempt failed
 * lately goes after every other one.  -1 = nothing to dial now. */
int pool_pick_slot(bot_state_t *state, time_t now, time_t *soonest) {
  int gap = state->pool_order_known ? state->pool_order.gap : 0;
  int lagging = -1;
  *soonest = 0;
  for (int i = 0; i < state->server_count; i++) {
    const server_block_t *b = &state->server_blocks[i];
    if (b->kind == SB_BANNED_PERM) continue;
    time_t back = 0;
    if (b->kind != SB_NONE && b->until > now) back = b->until;
    if (gap > 0 && b->last_dial && now - b->last_dial < gap && b->last_dial + gap > back)
      back = b->last_dial + gap;
    if (back) {
      if (*soonest == 0 || back < *soonest) *soonest = back;
      continue;
    }
    if (b->last_fail && now - b->last_fail < POOL_FAIL_AVOID) {
      if (lagging < 0) lagging = i;
      continue;
    }
    return i;
  }
  return lagging;
}

/* ---- server rebalance force (CMD_BOT_MOVE) ------------------------------ */

/* bot move <bot> server <s>: go to that pool entry now (one bot, so no
 * burst); the R| order may move it back at its next rebalance. */
bool pool_move_to_entry(bot_state_t *state, const char *entry) {
  if (state->hub_count == 0 || !entry || !entry[0]) return false;
  int to = -1;
  for (int i = 0; i < state->server_count && to < 0; i++)
    if (strcmp(state->dial_uuid[i], entry) == 0 &&
        state->server_blocks[i].kind != SB_BANNED_PERM)
      to = i;
  int cur = state->irc_server_idx;
  if (to < 0 || ((state->status & S_CONNECTED) && cur == to)) return false;
  log_message(L_INFO, state, "[POOL] Moving to %s (bot move from the hub console)\n",
              state->server_list[to]);
  state->current_server_index = to;
  state->jump_slot1 = to + 1;
  if (state->status & S_CONNECTED) {
    irc_printf(state, "QUIT :Moving servers\r\n");
    irc_disconnect(state);
  }
  return true;
}

bool pool_move_to_first(bot_state_t *state) {
  if (state->hub_count == 0 || !state->pool_order_known || !(state->status & S_CONNECTED))
    return false;
  int cur = state->irc_server_idx;
  const char *on = cur >= 0 && cur < state->server_count ? state->dial_uuid[cur] : "";
  /* the first entry of the order this bot can dial */
  int to = -1;
  for (int k = 0; k < state->pool_order.n && to < 0; k++)
    for (int i = 0; i < state->server_count && to < 0; i++)
      if (strcmp(state->dial_uuid[i], state->pool_order.ids[k]) == 0) to = i;
  if (to < 0 || strcmp(on, state->dial_uuid[to]) == 0) return false;
  log_message(L_INFO, state, "[POOL] Rebalance: moving to %s, the first server of my order\n",
              state->server_list[to]);
  state->current_server_index = to;
  state->jump_slot1 = to + 1;
  irc_printf(state, "QUIT :Rebalancing servers\r\n");
  irc_disconnect(state);
  return true;
}
