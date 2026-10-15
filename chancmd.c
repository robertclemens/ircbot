/* Bot commands for hubless networks (irchub docs/modes.md §5.2):
 *
 *   chanmode <#c> [<modes> [args]|-]     = console `channel mode`
 *   chanset  <#c|default> [...]          = console `channel set`
 *   +ban <#c|*> <mask> [min|perm] [sticky] [reason] / -ban / bans
 *                                        = console `ban add/del/list`
 *
 * They write this bot's own C| / D| / B| (and the c| key) with LWW stamps,
 * through the same record codecs the hub's lines use (chancfg_local_*), and
 * apply at once: a connected hub gets the lines, the config is saved, the
 * channel sweeps run.  The dispatcher refuses them under opt 'h' like chkey;
 * this file asks admin_change_refused again, so nothing here runs gated off.
 * Replies go out as PRIVMSG to the asker, which a ~A2S command seals.
 * Every ban is checked against bots and authorised users first (§6.2). */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bot.h"


static void say(bot_state_t *state, const char *nick, const char *text) {
  irc_printf(state, "PRIVMSG %s :%s\r\n", nick, text);
}

static bool refused(bot_state_t *state, const char *nick, const char *cmd) {
  if (!admin_change_refused(state))
    return false;
  irc_printf(state, "PRIVMSG %s :Error: '%s' is disabled -- network is in "
                    "hub-only-mutation mode (opt 'h'). Use the hub console.\r\n",
             nick, cmd);
  return true;
}

/* A managed channel by name, or NULL (reply sent). */
static chan_t *find_chan(bot_state_t *state, const char *nick, const char *name) {
  if (!name || (name[0] != '#' && name[0] != '&') || strlen(name) >= MAX_CHAN) {
    say(state, nick, "Error: give a channel name (#channel).");
    return NULL;
  }
  chan_t *c = channel_find(state, name);
  if (!c || !c->is_managed) {
    irc_printf(state, "PRIVMSG %s :Error: %s is not in my channel list.\r\n",
               nick, name);
    return NULL;
  }
  return c;
}

/* --- chanmode ------------------------------------------------------------- */

static bool key_ok(const char *k) {
  size_t n = strlen(k);
  if (n == 0 || n >= MAX_KEY)
    return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)k[i];
    if (ch <= 0x20 || ch == 0x7f || ch == ',' || ch == '|')
      return false;
  }
  return true;
}

/* §3.2.  modes = the letters token; args = the rest.  On success `stored` is
 * the C| modes field ("+stnkl 20"), *key_set / *key_clear the key change. */
static bool parse_modes(const char *modes, char **args, int nargs, char *stored,
                        size_t stored_size, const char **key, bool *key_clear,
                        char *err, size_t err_size) {
  char seen[128] = {0};
  char letters[40];
  size_t ll = 0;
  char sign = 0;
  int ai = 0;
  long limit = 0;
  bool plus_s = false, plus_p = false;
  *key = NULL;
  *key_clear = false;
  bool adding = true;
  for (const char *m = modes; *m; m++) {
    if (*m == '+' || *m == '-') {
      adding = *m == '+';
      continue;
    }
    if (!strchr("imnpstkl", *m)) {
      snprintf(err, err_size, "'%c' is not a channel mode I manage (i m n p s t k l)", *m);
      return false;
    }
    if (seen[(unsigned char)*m & 0x7f]) {
      snprintf(err, err_size, "'%c' given twice", *m);
      return false;
    }
    seen[(unsigned char)*m & 0x7f] = 1;
    if (ll + 3 >= sizeof(letters)) {
      snprintf(err, err_size, "mode string too long");
      return false;
    }
    char want = adding ? '+' : '-';
    if (sign != want) {
      letters[ll++] = want;
      sign = want;
    }
    letters[ll++] = *m;
    if (adding && *m == 's') plus_s = true;
    if (adding && *m == 'p') plus_p = true;
    if (*m == 'k') {
      if (adding) {
        if (ai >= nargs || !key_ok(args[ai])) {
          snprintf(err, err_size, "+k needs a key (1..%d bytes, no space, comma or control character)", MAX_KEY - 1);
          return false;
        }
        *key = args[ai++];
      } else {
        *key_clear = true;
      }
    } else if (*m == 'l' && adding) {
      char *end;
      if (ai >= nargs) {
        snprintf(err, err_size, "+l needs a limit (1..99999)");
        return false;
      }
      const char *a = args[ai++];
      limit = strtol(a, &end, 10);
      if (*a == '\0' || *end != '\0' || strlen(a) > 5 || limit < 1 ||
          limit > 99999) {
        snprintf(err, err_size, "the limit must be 1..99999");
        return false;
      }
    }
  }
  letters[ll] = '\0';
  if (ll == 0) {
    snprintf(err, err_size, "no modes given");
    return false;
  }
  if (ai != nargs) {
    snprintf(err, err_size, "wrong number of arguments for the modes");
    return false;
  }
  if (plus_s && plus_p) {
    snprintf(err, err_size, "+s and +p together are refused");
    return false;
  }
  int w = limit > 0 ? snprintf(stored, stored_size, "%s %ld", letters, limit)
                    : snprintf(stored, stored_size, "%s", letters);
  if (w < 0 || (size_t)w > C_MODES_MAX) {
    snprintf(err, err_size, "mode string too long");
    return false;
  }
  return true;
}

static void show_modes(bot_state_t *state, const char *nick, chan_t *c) {
  char line[256];
  snprintf(line, sizeof(line), "%s: stored modes %s%s, key %s, %s", c->name,
           chancfg_get_modes(state, c),
           (c->cfg_active && c->cfg_ts > 0 && c->cfg_modes[0]) ? ""
           : " (default)", c->key[0] ? "set" : "none",
           chancfg_get(state, c, CS_ENFORCEMODES) ? "+enforcemodes"
                                                  : "-enforcemodes");
  say(state, nick, line);
}

void chancmd_chanmode(bot_state_t *state, const char *nick,
                      const user_record_t *who, char *args) {
  (void)who;
  if (refused(state, nick, "chanmode"))
    return;
  char *save = NULL;
  char *name = args ? strtok_r(args, " ", &save) : NULL;
  if (!name) {
    say(state, nick, "Syntax: chanmode <#channel> [<modes> [args]|-]");
    return;
  }
  chan_t *c = find_chan(state, nick, name);
  if (!c)
    return;
  char *modes = strtok_r(NULL, " ", &save);
  if (!modes) {
    show_modes(state, nick, c);
    return;
  }
  char *av[8];
  int nav = 0;
  char *t;
  while ((t = strtok_r(NULL, " ", &save)) != NULL) {
    if (nav >= 8) {
      say(state, nick, "Error: too many arguments.");
      return;
    }
    av[nav++] = t;
  }

  char stored[C_MODES_MAX + 1], err[160];
  const char *key = NULL;
  bool key_clear = false;
  if (strcmp(modes, "-") == 0 && nav == 0) {
    stored[0] = '\0'; /* back to the network default */
  } else if (!parse_modes(modes, av, nav, stored, sizeof(stored), &key,
                          &key_clear, err, sizeof(err))) {
    irc_printf(state, "PRIVMSG %s :Error: bad mode: %s.\r\n", nick, err);
    return;
  }

  bool key_changed = false;
  char old_key[MAX_KEY];
  snprintf(old_key, sizeof(old_key), "%s", c->key);
  if (key && strcmp(c->key, key) != 0) {
    snprintf(c->key, sizeof(c->key), "%s", key);
    key_changed = true;
  } else if (key_clear && c->key[0]) {
    c->key[0] = '\0';
    key_changed = true;
  }
  if (!chancfg_local_c(state, c, stored, c->cfg_settings)) {
    snprintf(c->key, sizeof(c->key), "%s", old_key);
    say(state, nick, "Error: could not store the modes.");
    return;
  }
  if (key_changed) {
    c->timestamp = lww_next_ts(c->timestamp);
    hub_client_push_config(state);
  }
  secure_wipe(old_key, sizeof(old_key));

  char sum[64];
  if (c->status == C_IN && c->i_am_opped) {
    if (chanmode_apply_stored(state, c, sum, sizeof(sum)) < 0)
      snprintf(sum, sizeof(sum), "could not apply");
    irc_printf(state, "PRIVMSG %s :%s: modes stored (%s) and applied: %s.\r\n",
               nick, c->name, stored[0] ? stored : "network default", sum);
  } else {
    irc_printf(state, "PRIVMSG %s :%s: modes stored (%s); not applied, I am "
                      "not opped there.\r\n", nick, c->name,
               stored[0] ? stored : "network default");
  }
  if (strchr(stored, 'l') && chancfg_get(state, c, CS_DYNAMICLIMIT))
    say(state, nick, "Warning: +dynamiclimit is on and overrides the fixed limit.");
}

/* --- chanset -------------------------------------------------------------- */

static void show_settings(bot_state_t *state, const char *nick, chan_t *c) {
  bool net = c == NULL;
  char row[360];
  size_t rl = 0;
  row[0] = '\0';
  irc_printf(state, "PRIVMSG %s :Settings for %s (c = channel, n = network "
                    "default, b = built-in):\r\n", nick, net ? "default" : c->name);
  for (int i = 0; i < (int)CS_COUNT + (int)FL_COUNT; i++) {
    const char *name = chancfg_item_name(i, net);
    if (!name)
      continue;
    char val[24];
    if (i < CS_COUNT) {
      snprintf(val, sizeof(val), "%ld", chancfg_get(state, c, (cset_id_t)i));
    } else {
      int n, s;
      if (chancfg_get_flood(state, c, (flood_kind_t)(i - CS_COUNT), &n, &s))
        snprintf(val, sizeof(val), "%d:%d", n, s);
      else
        snprintf(val, sizeof(val), "off");
    }
    static const char SRC[3] = {'b', 'n', 'c'};
    char item[80];
    int il = snprintf(item, sizeof(item), "%s=%s(%c)  ", name, val,
                      SRC[chancfg_item_source(state, c, i)]);
    if (rl + (size_t)il >= sizeof(row)) {
      say(state, nick, row);
      rl = 0;
      row[0] = '\0';
    }
    memcpy(row + rl, item, (size_t)il + 1);
    rl += (size_t)il;
  }
  if (rl)
    say(state, nick, row);
}

void chancmd_chanset(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args) {
  (void)who;
  if (refused(state, nick, "chanset"))
    return;
  char *save = NULL;
  char *name = args ? strtok_r(args, " ", &save) : NULL;
  if (!name) {
    say(state, nick, "Syntax: chanset <#channel|default> [+opt -opt ...] "
                     "[<name> <value|default>] [flood <type> <N:S|off|default>]");
    return;
  }
  bool net = strcasecmp(name, "default") == 0;
  chan_t *c = net ? NULL : find_chan(state, nick, name);
  if (!net && !c)
    return;
  char *tok = strtok_r(NULL, " ", &save);
  if (!tok) {
    show_settings(state, nick, c);
    return;
  }

  char sets[D_SETTINGS_MAX + 1], why[160];
  snprintf(sets, sizeof(sets), "%s", net ? state->net_settings : c->cfg_settings);
  int edits = 0;
  while (tok) {
    char full[48];
    const char *item, *val;
    if ((tok[0] == '+' || tok[0] == '-') && tok[1]) {
      item = tok + 1;
      val = tok[0] == '+' ? "1" : "0";
      if (!chancfg_setting_is_flag(item)) {
        irc_printf(state, "PRIVMSG %s :Error: '%s' is not an on/off option; "
                          "give it a value.\r\n", nick, item);
        return;
      }
    } else if (strcasecmp(tok, "key") == 0) {
      say(state, nick, "Error: the key moved: use chanmode <#channel> +k <key>.");
      return;
    } else if (strcmp(tok, "flood") == 0) {
      char *type = strtok_r(NULL, " ", &save);
      val = strtok_r(NULL, " ", &save);
      if (!type || !val || strlen(type) > 8) {
        say(state, nick, "Syntax: flood <type> <N:S|off|default>");
        return;
      }
      bool bot = strcmp(type, "cmd") == 0 || strcmp(type, "msg") == 0 ||
                 strcmp(type, "ctcp") == 0;
      /* "ctcp" is both a channel and a bot flood: on `default` the channel
       * one is `flood ctcp`, the bot one `flood bot ctcp` is not offered --
       * cmd and msg are unambiguous, ctcp picks the channel flood. */
      snprintf(full, sizeof(full), "%s %s",
               (net && bot && strcmp(type, "ctcp") != 0) ? "bflood" : "flood",
               type);
      item = full;
    } else if (strcmp(tok, "bflood") == 0 && net) {
      char *type = strtok_r(NULL, " ", &save);
      val = strtok_r(NULL, " ", &save);
      if (!type || !val || strlen(type) > 8) {
        say(state, nick, "Syntax: bflood <cmd|msg|ctcp> <N:S|off|default>");
        return;
      }
      snprintf(full, sizeof(full), "bflood %s", type);
      item = full;
    } else {
      item = tok;
      val = strtok_r(NULL, " ", &save);
      if (!val) {
        irc_printf(state, "PRIVMSG %s :Error: '%s' needs a value.\r\n", nick,
                   item);
        return;
      }
    }
    if (!chancfg_settings_edit(sets, sizeof(sets), net, item, val, why,
                               sizeof(why))) {
      irc_printf(state, "PRIVMSG %s :Error: %s.\r\n", nick, why);
      return;
    }
    edits++;
    tok = strtok_r(NULL, " ", &save);
  }
  if (edits == 0)
    return;
  bool ok = net ? chancfg_local_d(state, state->net_modes, sets)
                : chancfg_local_c(state, c, c->cfg_modes, sets);
  if (!ok) {
    say(state, nick, "Error: could not store the settings.");
    return;
  }
  irc_printf(state, "PRIVMSG %s :%s: %d setting%s changed (now: %s).\r\n", nick,
             net ? "default" : c->name, edits, edits == 1 ? "" : "s",
             sets[0] ? sets : "all built-in");
}

/* --- bans ------------------------------------------------------------------ */

static bool all_digits(const char *s) {
  if (!*s)
    return false;
  for (; *s; s++)
    if (*s < '0' || *s > '9')
      return false;
  return true;
}

static bool mask_ok(const char *m) {
  size_t n = strlen(m);
  if (n < 5 || n > BAN_MASK_MAX || !strchr(m, '!') || !strchr(m, '@') ||
      strchr(m, '|'))
    return false;
  const char *bang = strchr(m, '!');
  return strchr(bang, '@') != NULL;
}

/* chan "*" or a managed channel; *c_out set for a channel. */
static bool ban_target(bot_state_t *state, const char *nick, const char *name,
                       chan_t **c_out) {
  *c_out = NULL;
  if (name && strcmp(name, "*") == 0)
    return true;
  *c_out = find_chan(state, nick, name);
  return *c_out != NULL;
}

void chancmd_ban_add(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args) {
  if (refused(state, nick, "+ban"))
    return;
  char *save = NULL;
  char *chan = args ? strtok_r(args, " ", &save) : NULL;
  char *mask = chan ? strtok_r(NULL, " ", &save) : NULL;
  if (!mask) {
    say(state, nick, "Syntax: +ban <#channel|*> <nick!user@host> [<minutes>|perm] [sticky] [reason]");
    return;
  }
  chan_t *c;
  if (!ban_target(state, nick, chan, &c))
    return;
  if (!mask_ok(mask)) {
    say(state, nick, "Error: the mask must look like nick!user@host (wildcards allowed).");
    return;
  }

  /* optional: minutes|perm, then sticky, then the reason is the rest */
  time_t expires = 0;
  bool sticky = false;
  const char *rest = save ? save : "";
  while (*rest == ' ')
    rest++;
  const char *p = rest;
  size_t wl = strcspn(p, " ");
  if (wl > 0) {
    char w[16] = {0};
    if (wl < sizeof(w)) {
      memcpy(w, p, wl);
      if (strcmp(w, "perm") == 0) {
        p += wl;
      } else if (all_digits(w) && wl <= 6) {
        long mins = strtol(w, NULL, 10);
        if (mins < 1 || mins > 525600) {
          say(state, nick, "Error: minutes must be 1..525600 (or perm).");
          return;
        }
        expires = time(NULL) + (time_t)mins * 60;
        p += wl;
      }
    }
  }
  while (*p == ' ')
    p++;
  wl = strcspn(p, " ");
  if (wl == 6 && strncmp(p, "sticky", 6) == 0) {
    sticky = true;
    p += wl;
  }
  while (*p == ' ')
    p++;
  const char *reason = p;

  /* §6.2: never a bot or an authorised user */
  char hit[128];
  hit[0] = '\0';
  bool ok = true;
  if (c) {
    ok = chanenf_ban_allowed(state, c, mask, hit, sizeof(hit));
  } else {
    for (chan_t *k = state->chanlist; k && ok; k = k->next)
      if (k->is_managed && !chanenf_ban_allowed(state, k, mask, hit, sizeof(hit)))
        ok = false;
    if (ok)
      ok = chanenf_ban_allowed(state, NULL, mask, hit, sizeof(hit));
  }
  if (!ok) {
    irc_printf(state, "PRIVMSG %s :Refused: %s would hit %s -- a bot or an "
                      "authorised user is never banned.\r\n", nick, mask,
               hit[0] ? hit : "one of them");
    return;
  }
  if (!chancfg_local_ban(state, c ? c->name : "*", mask, expires,
                         sticky ? "s" : "", who ? who->name : "admin", reason,
                         false)) {
    say(state, nick, "Error: ban not stored (list full or bad value).");
    return;
  }
  irc_printf(state, "PRIVMSG %s :Ban added: %s %s (%s%s).\r\n", nick,
             c ? c->name : "*", mask, expires ? "timed" : "permanent",
             sticky ? ", sticky" : "");
}

void chancmd_ban_del(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args) {
  if (refused(state, nick, "-ban"))
    return;
  char *save = NULL;
  char *chan = args ? strtok_r(args, " ", &save) : NULL;
  char *mask = chan ? strtok_r(NULL, " ", &save) : NULL;
  if (!mask) {
    say(state, nick, "Syntax: -ban <#channel|*> <nick!user@host>");
    return;
  }
  chan_t *c;
  if (!ban_target(state, nick, chan, &c))
    return;
  const char *cn = c ? c->name : "*";
  if (!chancfg_ban_get(state, cn, mask) ||
      !chancfg_local_ban(state, cn, mask, 0, "", who ? who->name : "admin", "",
                         true)) {
    irc_printf(state, "PRIVMSG %s :Error: no ban %s on %s.\r\n", nick, mask, cn);
    return;
  }
  irc_printf(state, "PRIVMSG %s :Ban removed: %s %s.\r\n", nick, cn, mask);
}

#define BANS_ROWS 30

void chancmd_bans(bot_state_t *state, const char *nick, char *args) {
  char *save = NULL;
  char *chan = args ? strtok_r(args, " ", &save) : NULL;
  int shown = 0, total = 0;
  time_t now = time(NULL);
  for (int i = 0; i < state->cfg_ban_count; i++) {
    const cfg_ban_t *b = &state->cfg_bans[i];
    if (!b->active)
      continue;
    if (chan && strcasecmp(b->chan, chan) != 0 && strcmp(b->chan, "*") != 0)
      continue;
    if (b->expires && b->expires <= now)
      continue;
    total++;
    if (shown >= BANS_ROWS)
      continue;
    char left[32];
    if (b->expires)
      snprintf(left, sizeof(left), "%ldm", (long)((b->expires - now + 59) / 60));
    else
      snprintf(left, sizeof(left), "perm");
    irc_printf(state, "PRIVMSG %s :%s %s %s%s by %s%s%s\r\n", nick, b->chan,
               b->mask, left, strchr(b->flags, 's') ? " sticky" : "", b->setter,
               b->reason[0] ? ": " : "", b->reason);
    shown++;
  }
  if (total == 0)
    say(state, nick, "No network bans.");
  else if (total > shown)
    irc_printf(state, "PRIVMSG %s :... and %d more.\r\n", nick, total - shown);
}
