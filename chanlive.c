/* Live channel state from the server (modes.md §5.4): 005 values, the mode
 * letters / key / limit of each channel (324 + MODE), its ban list
 * (367 + MODE +b/-b), and the election-driven "apply the stored modes" job.
 * Everything here is volatile; nothing is persisted or sent to a hub.
 * Server data is hostile: every token is length-checked before it is copied
 * and a list can never grow past isupport_ban_cap(). */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

/* --- 005 (RPL_ISUPPORT) -------------------------------------------------- */

void isupport_reset(bot_state_t *state) {
  isupport_t *is = &state->isup;
  memset(is, 0, sizeof(*is));
  is->modes = ISUPPORT_MODES_DEFAULT;
  is->nicklen = NICKLEN_DEFAULT;
  snprintf(is->prefix_modes, sizeof(is->prefix_modes), "ov");
  snprintf(is->prefix_syms, sizeof(is->prefix_syms), "@+");
  snprintf(is->cm_a, sizeof(is->cm_a), "beI");
  snprintf(is->cm_b, sizeof(is->cm_b), "k");
  snprintf(is->cm_c, sizeof(is->cm_c), "l");
  snprintf(is->cm_d, sizeof(is->cm_d), "imnpst");
}

/* Unix timestamp: 1..20 digits, overflow-checked; 0 when malformed. */
static time_t parse_ts(const char *s) {
  size_t len = s ? strlen(s) : 0;
  if (len == 0 || len > 20)
    return 0;
  for (size_t i = 0; i < len; i++)
    if (s[i] < '0' || s[i] > '9')
      return 0;
  errno = 0;
  long long v = strtoll(s, NULL, 10);
  if (errno != 0 || v < 0 || (long long)(time_t)v != v)
    return 0;
  return (time_t)v;
}

static bool all_digits(const char *s, size_t len) {
  if (len == 0 || len > 6)
    return false;
  for (size_t i = 0; i < len; i++)
    if (s[i] < '0' || s[i] > '9')
      return false;
  return true;
}

static void copy_field(char *dst, size_t dsz, const char *src, size_t len) {
  if (len >= dsz)
    len = dsz - 1;
  memcpy(dst, src, len);
  dst[len] = '\0';
}

static void isupport_token(bot_state_t *state, const char *tok) {
  isupport_t *is = &state->isup;
  bool neg = (tok[0] == '-');
  if (neg)
    tok++;
  const char *eq = strchr(tok, '=');
  size_t nl = eq ? (size_t)(eq - tok) : strlen(tok);
  const char *val = eq ? eq + 1 : "";
  size_t vl = strlen(val);

  if (nl == 5 && strncmp(tok, "MODES", 5) == 0) {
    if (neg) { is->modes = ISUPPORT_MODES_DEFAULT; return; }
    if (vl == 0) { is->modes = ISUPPORT_MODES_MAX; return; } /* no limit */
    if (all_digits(val, vl)) {
      long v = strtol(val, NULL, 10);
      if (v >= 1)
        is->modes = v > ISUPPORT_MODES_MAX ? ISUPPORT_MODES_MAX : (int)v;
    }
  } else if (nl == 7 && strncmp(tok, "MAXLIST", 7) == 0) {
    if (neg) { is->maxlist_b = 0; return; }
    /* "beI:100,k:5": a letter group, a colon, a number */
    const char *p = val;
    while (*p) {
      const char *colon = strchr(p, ':');
      if (!colon)
        break;
      const char *end = strchr(colon, ',');
      size_t numl = end ? (size_t)(end - colon - 1) : strlen(colon + 1);
      if (memchr(p, 'b', (size_t)(colon - p)) && all_digits(colon + 1, numl)) {
        long v = strtol(colon + 1, NULL, 10);
        if (v >= 1)
          is->maxlist_b = (int)v;
      }
      if (!end)
        break;
      p = end + 1;
    }
  } else if (nl == 7 && strncmp(tok, "MAXBANS", 7) == 0) {
    if (is->maxlist_b == 0 && all_digits(val, vl)) {
      long v = strtol(val, NULL, 10);
      if (v >= 1)
        is->maxlist_b = (int)v;
    }
  } else if (nl == 7 && strncmp(tok, "NICKLEN", 7) == 0) {
    if (neg) { is->nicklen = NICKLEN_DEFAULT; return; }
    if (all_digits(val, vl)) {
      long v = strtol(val, NULL, 10);
      if (v >= 1)
        is->nicklen = (int)v;
    }
  } else if (nl == 6 && strncmp(tok, "PREFIX", 6) == 0) {
    if (neg) {
      snprintf(is->prefix_modes, sizeof(is->prefix_modes), "ov");
      snprintf(is->prefix_syms, sizeof(is->prefix_syms), "@+");
      return;
    }
    /* "(ohv)@%+": equal numbers of mode letters and symbols, at most 8 */
    if (val[0] != '(')
      return;
    const char *close = strchr(val, ')');
    if (!close)
      return;
    size_t ml = (size_t)(close - val - 1), sl = strlen(close + 1);
    if (ml == 0 || ml != sl || ml >= sizeof(is->prefix_modes))
      return;
    for (size_t i = 0; i < ml; i++)
      if (!isalpha((unsigned char)val[1 + i]))
        return;
    copy_field(is->prefix_modes, sizeof(is->prefix_modes), val + 1, ml);
    copy_field(is->prefix_syms, sizeof(is->prefix_syms), close + 1, sl);
  } else if (nl == 9 && strncmp(tok, "CHANMODES", 9) == 0) {
    if (neg)
      return;
    char *fields[4] = {is->cm_a, is->cm_b, is->cm_c, is->cm_d};
    size_t fsz[4] = {sizeof(is->cm_a), sizeof(is->cm_b), sizeof(is->cm_c),
                     sizeof(is->cm_d)};
    char tmp[4][64];
    const char *p = val;
    for (int i = 0; i < 4; i++) {
      const char *comma = strchr(p, ',');
      size_t fl = comma ? (size_t)(comma - p) : strlen(p);
      if (i < 3 && !comma)
        return; /* malformed: keep what we had */
      /* A, B, C name the modes that take arguments: a clipped one would
       * misread every MODE line, so an oversized one is refused.  D (the
       * flag modes) is only ever looked up for a letter, so it is cut. */
      if (fl >= fsz[i]) {
        if (i < 3)
          return;
        fl = fsz[i] - 1;
      }
      memcpy(tmp[i], p, fl);
      tmp[i][fl] = '\0';
      if (comma) p = comma + 1;
      else p += fl;
    }
    for (int i = 0; i < 4; i++)
      snprintf(fields[i], fsz[i], "%s", tmp[i]);
  }
}

void isupport_parse(bot_state_t *state, char *params) {
  char *save;
  char *tok = strtok_r(params, " ", &save); /* our nick */
  while ((tok = strtok_r(NULL, " ", &save)) != NULL) {
    if (tok[0] == ':')
      break; /* trailing "are supported by this server" */
    if (strlen(tok) < 120)
      isupport_token(state, tok);
  }
}

bool isupport_is_prefix_mode(const bot_state_t *state, char m) {
  return m != '\0' && strchr(state->isup.prefix_modes, m) != NULL;
}

bool isupport_mode_has_arg(const bot_state_t *state, char m, bool adding) {
  const isupport_t *is = &state->isup;
  if (isupport_is_prefix_mode(state, m))
    return true;
  if (strchr(is->cm_a, m) || strchr(is->cm_b, m))
    return true;
  if (strchr(is->cm_c, m))
    return adding;
  return false;
}

/* Longest member nick we accept: the server's NICKLEN, held to our buffers. */
int isupport_nicklen(const bot_state_t *state) {
  int n = state->isup.nicklen > 0 ? state->isup.nicklen : NICKLEN_DEFAULT;
  return n < MAX_MEMBER_NICK - 1 ? n : MAX_MEMBER_NICK - 1;
}

int isupport_ban_cap(const bot_state_t *state) {
  int n = state->isup.maxlist_b > 0 ? state->isup.maxlist_b : MAXLIST_DEFAULT;
  return n < BAN_LIST_CAP ? n : BAN_LIST_CAP;
}

/* --- live modes ---------------------------------------------------------- */

uint64_t chan_live_bit(char letter) {
  if (letter >= 'a' && letter <= 'z')
    return (uint64_t)1 << (letter - 'a');
  if (letter >= 'A' && letter <= 'Z')
    return (uint64_t)1 << (26 + (letter - 'A'));
  return 0;
}

bool chan_live_has(const chan_t *c, char letter) {
  uint64_t b = chan_live_bit(letter);
  return b && (c->live_flags & b);
}

static void ban_free_all(chan_t *c) {
  for (int i = 0; i < c->ban_count; i++)
    free(c->bans[i].mask);
  free(c->bans);
  c->bans = NULL;
  c->ban_count = c->ban_cap = 0;
}

void channel_live_reset(chan_t *c) {
  ban_free_all(c);
  free(c->flood); /* flood windows start afresh with each stay */
  c->flood = NULL;
  c->live_flags = 0;
  c->live_key[0] = '\0';
  c->live_limit = 0;
  c->live_known = false;
  c->live_created = 0;
  c->ban_list_open = false;
  c->ban_list_known = false;
  c->ban_overflow_logged = false;
  c->who_done = false;
}

void chanlive_ban_add(bot_state_t *state, chan_t *c, const char *mask,
                      const char *setter, time_t when) {
  size_t ml = mask ? strlen(mask) : 0;
  if (ml == 0 || ml >= MAX_MASK_LEN)
    return; /* never store a clipped mask */
  for (int i = 0; i < c->ban_count; i++)
    if (strcasecmp(c->bans[i].mask, mask) == 0)
      return;
  if (c->ban_count >= isupport_ban_cap(state)) {
    if (!c->ban_overflow_logged) {
      c->ban_overflow_logged = true;
      log_message(L_INFO, state,
                  "[MODE] Ban list of %s is past %d entries; not tracking "
                  "more\n", c->name, isupport_ban_cap(state));
    }
    return;
  }
  if (c->ban_count == c->ban_cap) {
    int cap = c->ban_cap ? c->ban_cap * 2 : 8;
    if (cap > BAN_LIST_CAP)
      cap = BAN_LIST_CAP;
    live_ban_t *nb = realloc(c->bans, (size_t)cap * sizeof(*nb));
    if (!nb)
      return;
    c->bans = nb;
    c->ban_cap = cap;
  }
  char *copy = malloc(ml + 1);
  if (!copy)
    return;
  memcpy(copy, mask, ml + 1);
  live_ban_t *b = &c->bans[c->ban_count++];
  b->mask = copy;
  b->when = when;
  snprintf(b->setter, sizeof(b->setter), "%.*s", (int)sizeof(b->setter) - 1,
           setter ? setter : "");
}

void chanlive_ban_del(chan_t *c, const char *mask) {
  for (int i = 0; i < c->ban_count; i++) {
    if (strcasecmp(c->bans[i].mask, mask) == 0) {
      free(c->bans[i].mask);
      c->bans[i] = c->bans[--c->ban_count];
      return;
    }
  }
}

void chanlive_ban_list_end(chan_t *c) {
  if (!c->ban_list_open)
    ban_free_all(c); /* 368 with no 367: the list is empty */
  c->ban_list_open = false;
  c->ban_list_known = true;
}

static roster_entry_t *roster_by_nick(chan_t *c, const char *nick) {
  for (int i = 0; i < c->roster_count; i++)
    if (strcasecmp(c->roster[i].nick, nick) == 0)
      return &c->roster[i];
  return NULL;
}

void chanlive_apply(bot_state_t *state, chan_t *c, const char *modes,
                    char *args, bool from_324) {
  if (from_324) {
    c->live_flags = 0;
    c->live_key[0] = '\0';
    c->live_limit = 0;
    c->live_known = true;
  }
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
      continue; /* malformed: an argument is missing */

    if (ch == 'b') {
      if (a && !from_324) {
        if (adding) chanlive_ban_add(state, c, a, "", time(NULL));
        else chanlive_ban_del(c, a);
      }
    } else if (ch == 'k') {
      if (adding) {
        c->live_flags |= chan_live_bit('k');
        if (a)
          snprintf(c->live_key, sizeof(c->live_key), "%s", a);
      } else {
        c->live_flags &= ~chan_live_bit('k');
        c->live_key[0] = '\0';
      }
    } else if (ch == 'l') {
      if (adding && a && all_digits(a, strlen(a))) {
        c->live_flags |= chan_live_bit('l');
        c->live_limit = strtol(a, NULL, 10);
      } else if (!adding) {
        c->live_flags &= ~chan_live_bit('l');
        c->live_limit = 0;
      }
    } else if (isupport_is_prefix_mode(state, ch)) {
      roster_entry_t *r = a ? roster_by_nick(c, a) : NULL;
      if (r && ch == 'h')
        r->is_halfop = adding;
      else if (r && ch == 'v')
        r->is_voice = adding;
      /* 'o' is kept by channel_handle_mode_change (it also reacts to us) */
    } else if (!has_arg && isalpha((unsigned char)ch)) {
      uint64_t bit = chan_live_bit(ch);
      if (adding) c->live_flags |= bit;
      else c->live_flags &= ~bit;
    }
  }
}

/* "<me> <chan> <rest...>": split off nick and channel, return the rest. */
static chan_t *numeric_chan(bot_state_t *state, char *params, char **rest) {
  char *save;
  if (!strtok_r(params, " ", &save))
    return NULL;
  char *chan = strtok_r(NULL, " ", &save);
  if (!chan)
    return NULL;
  *rest = save;
  return channel_find(state, chan);
}

void chanlive_numeric(bot_state_t *state, const char *command, char *params) {
  char buf[1024];
  if (strlen(params) >= sizeof(buf))
    return; /* no real 324/329/367 is this long */
  memcpy(buf, params, strlen(params) + 1);
  char *rest = NULL;
  chan_t *c = numeric_chan(state, buf, &rest);
  if (!c || !rest)
    return;
  if (strcmp(command, "324") == 0) {
    char *save;
    char *modes = strtok_r(rest, " ", &save);
    if (modes)
      chanlive_apply(state, c, modes, save, true);
    c->enf_dirty = true;
  } else if (strcmp(command, "329") == 0) {
    char *save;
    char *ts = strtok_r(rest, " ", &save);
    c->live_created = parse_ts(ts);
  } else if (strcmp(command, "367") == 0) {
    char *save;
    char *mask = strtok_r(rest, " ", &save);
    char *setter = strtok_r(NULL, " ", &save);
    char *ts = strtok_r(NULL, " ", &save);
    if (!mask)
      return;
    if (!c->ban_list_open) {
      ban_free_all(c);
      c->ban_list_open = true;
    }
    chanlive_ban_add(state, c, mask, setter ? setter : "",
                     parse_ts(ts));
  } else if (strcmp(command, "368") == 0) {
    chanlive_ban_list_end(c);
    c->enf_dirty = true;
  }
}

void chanlive_request(bot_state_t *state, chan_t *c) {
  irc_printf(state, "MODE %s\r\n", c->name);
  irc_printf(state, "MODE %s +b\r\n", c->name);
}

bool chan_member_authorised(const bot_state_t *state, const chan_t *c,
                            const char *nick, bool *found) {
  if (found)
    *found = false;
  for (int i = 0; i < c->roster_count; i++) {
    if (strcasecmp(c->roster[i].nick, nick) == 0) {
      if (found)
        *found = true;
      return auth_is_authorised(state, c->roster[i].hostmask);
    }
  }
  return false;
}

/* --- election kind `mode`: move the live modes to the stored ones --------- */

#define EMIT(...) do { if (!dry) irc_printf(__VA_ARGS__); } while (0)

/* Core of the mode apply / mode job.  skip_limit leaves +l/-l alone (the
 * dynamic limit owns it); dry only counts what it would send; require_known
 * refuses to act on a live-mode picture we never received (the enforcement
 * path -- the one-shot apply sends everything when unknown). */
static int mode_sync(bot_state_t *state, chan_t *c, bool skip_limit, bool dry,
                     bool require_known, char *summary, size_t summary_size);

/* The changes are held and leave packed, several per MODE line. */
int chanmode_sync(bot_state_t *state, chan_t *c, bool skip_limit, bool dry,
                  bool require_known, char *summary, size_t summary_size) {
  if (dry)
    return mode_sync(state, c, skip_limit, dry, require_known, summary,
                     summary_size);
  sendq_hold(state);
  int n = mode_sync(state, c, skip_limit, dry, require_known, summary,
                    summary_size);
  sendq_release(state);
  return n;
}

static int mode_sync(bot_state_t *state, chan_t *c, bool skip_limit, bool dry,
                     bool require_known, char *summary, size_t summary_size) {
  const char *spec = chancfg_get_modes(state, c);
  char want[128];
  if (strlen(spec) >= sizeof(want)) {
    snprintf(summary, summary_size, "stored modes too long");
    return -1;
  }
  memcpy(want, spec, strlen(spec) + 1);

  /* Stored form: "+stnkl 20" -- one letters token, then the limit if +l. */
  char *save;
  char *letters = strtok_r(want, " ", &save);
  char *limit_arg = strtok_r(NULL, " ", &save);
  char dir[128] = {0}; /* per letter: '+', '-' or 0 */
  long want_limit = 0;
  bool adding = true;
  if (!letters) {
    snprintf(summary, summary_size, "no stored modes");
    return -1;
  }
  for (const char *m = letters; *m; m++) {
    if (*m == '+') { adding = true; continue; }
    if (*m == '-') { adding = false; continue; }
    if (!strchr("imnpstkl", *m)) {
      snprintf(summary, summary_size, "stored modes hold '%c'", *m);
      return -1;
    }
    dir[(unsigned char)*m & 0x7f] = adding ? '+' : '-';
  }
  if (dir['l' & 0x7f] == '+') {
    if (!limit_arg || !all_digits(limit_arg, strlen(limit_arg)) ||
        (want_limit = strtol(limit_arg, NULL, 10)) < 1 || want_limit > 99999) {
      snprintf(summary, summary_size, "stored limit is not usable");
      return -1;
    }
  }
  bool known = c->live_known;
  if (require_known && !known) {
    snprintf(summary, summary_size, "live modes not known yet");
    return -1;
  }
  int queued = 0;
  for (const char *p = "imnpst"; *p; p++) {
    char d = dir[(unsigned char)*p & 0x7f];
    if (!d)
      continue;
    bool has = chan_live_has(c, *p);
    if (d == '+' && (!known || !has)) {
      EMIT(state, "MODE %s +%c\r\n", c->name, *p);
      queued++;
    } else if (d == '-' && (!known || has)) {
      EMIT(state, "MODE %s -%c\r\n", c->name, *p);
      queued++;
    }
  }
  char kd = dir['k' & 0x7f];
  bool key_ok = c->key[0] && !strpbrk(c->key, " ,\r\n\t");
  if (kd == '+' && key_ok) {
    bool live_k = chan_live_has(c, 'k');
    if (!known || !live_k || strcmp(c->live_key, c->key) != 0) {
      if (live_k && c->live_key[0] && strcmp(c->live_key, "*") != 0 &&
          strcmp(c->live_key, c->key) != 0) {
        EMIT(state, "MODE %s -k %s\r\n", c->name, c->live_key);
        queued++;
      }
      EMIT(state, "MODE %s +k %s\r\n", c->name, c->key);
      queued++;
    }
  } else if (kd == '-' && known && chan_live_has(c, 'k') && c->live_key[0] &&
             strcmp(c->live_key, "*") != 0) {
    EMIT(state, "MODE %s -k %s\r\n", c->name, c->live_key);
    queued++;
  }
  char ld = skip_limit ? 0 : dir['l' & 0x7f];
  if (ld == '+') {
    if (!known || !chan_live_has(c, 'l') || c->live_limit != want_limit) {
      EMIT(state, "MODE %s +l %ld\r\n", c->name, want_limit);
      queued++;
    }
  } else if (ld == '-' && (!known || chan_live_has(c, 'l'))) {
    EMIT(state, "MODE %s -l\r\n", c->name);
    queued++;
  }
  snprintf(summary, summary_size, "%d change%s queued", queued,
           queued == 1 ? "" : "s");
  return queued;
}

int chanmode_apply_stored(bot_state_t *state, chan_t *c, char *summary,
                          size_t summary_size) {
  return chanmode_sync(state, c, false, false, false, summary, summary_size);
}
