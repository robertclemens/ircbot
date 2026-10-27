#include <string.h>
#include <strings.h>
#include <time.h> // Ensure time() is available

#include "bot.h"
#include "glob_overlap.h"

/* Shared with the channel-access code, which matches a requester's hostmask
 * against the ban masks a 367 walk returns.  Case-insensitive, '*' and '?'. */
bool auth_wildcard_match(const char *pattern, const char *text) {
  const char *p = pattern;
  const char *t = text;
  const char *last_wildcard = NULL;
  const char *last_text_for_wildcard = NULL;

  while (*t) {
    if (*p == '*') {
      last_wildcard = p++;
      last_text_for_wildcard = t;
    } else if (*p == '?' || strncasecmp(p, t, 1) == 0) {
      p++;
      t++;
    } else if (last_wildcard) {
      p = last_wildcard + 1;
      t = ++last_text_for_wildcard;
    } else {
      return false;
    }
  }

  while (*p == '*') {
    p++;
  }

  return !*p;
}

/* auth_user_candidates: every active user record that has a public key and
 * owns an active mask matching user_host, each listed once (with the first
 * mask that matched).  Several records can match one hostmask (overlapping
 * wildcards); the caller tries each record's key and the one that verifies
 * wins.  Deliberately free of side effects: last_seen/last_used move only in
 * auth_mark_used(), after the sender has proven the key. */
int auth_user_candidates(bot_state_t *state, const char *user_host,
                         user_record_t **out, int *mask_idx, int max) {
  int n = 0;
  for (int i = 0; i < state->mask_record_count && n < max; i++) {
    mask_record_t *mr = &state->mask_records[i];
    if (!mr->is_active || mr->mask[0] == '\0') continue;
    if (!auth_wildcard_match(mr->mask, user_host)) continue;
    for (int j = 0; j < state->user_record_count; j++) {
      user_record_t *ur = &state->user_records[j];
      if (!ur->is_active || !ur->has_pubkey) continue;
      if (strcmp(ur->uuid, mr->uuid) != 0) continue;
      bool dup = false;
      for (int k = 0; k < n; k++)
        if (out[k] == ur) { dup = true; break; }
      if (!dup) {
        out[n] = ur;
        mask_idx[n] = i;
        n++;
      }
      break;
    }
  }
  if (n == 0)
    log_message(L_DEBUG, state, "[AUTH] no keyed user mask matched %s\n",
                user_host);
  return n;
}

/* True when `now` opens a new ACTIVITY_BUCKET after `prev`: the first use
 * within a clock hour, the only one reported to the hub. */
static bool activity_new_bucket(time_t prev, time_t now) {
  return prev / ACTIVITY_BUCKET < now / ACTIVITY_BUCKET;
}

/* Record a successful authentication.  Sets config_dirty so the debounced
 * flush in main.c persists last_seen/last_used locally; the first use of a
 * record within a clock hour is also reported to the hub (CMD_ACTIVITY),
 * with this use's exact time. */
void auth_mark_used(bot_state_t *state, user_record_t *u, int mask_idx,
                    time_t now) {
  if (u) {
    if (activity_new_bucket(u->last_seen, now)) u->act_pending = now;
    u->last_seen = now;
  }
  if (mask_idx >= 0 && mask_idx < state->mask_record_count) {
    mask_record_t *m = &state->mask_records[mask_idx];
    if (activity_new_bucket(m->last_used, now)) m->act_pending = now;
    m->last_used = now;
  }
  state->config_dirty = true;
  hub_client_send_activity(state);
}

// Strip leading '~' from the ident portion of nick!ident@host, writing the
// normalized form into out.  Handles both stored masks (which may lack '~' due
// to 396/NICK reconstruction without tilde) and live WHO results (which carry
// '~' when identd is absent).
static void strip_ident_tilde(const char *in, char *out, size_t out_size) {
  const char *bang = strchr(in, '!');
  if (!bang || bang[1] != '~') {
    snprintf(out, out_size, "%s", in);
    return;
  }
  size_t prefix = (size_t)(bang - in) + 1; // includes '!'
  if (prefix >= out_size) { snprintf(out, out_size, "%s", in); return; }
  memcpy(out, in, prefix);
  snprintf(out + prefix, out_size - prefix, "%s", bang + 2); // skip '~'
}

// auth_trusted_bot_by_host: wildcard-match user_host against the stored
// trusted-bot hostmasks.  Strict on the full mask by design (see
// ARCHITECTURE.md): the mask a peer publishes is the server-displayed one.
// trusted_bot_index_by_host returns the matching index or -1, so the
// const-state callers need no cast.
static int trusted_bot_index_by_host(const bot_state_t *state,
                                     const char *user_host) {
  if (state->trusted_bot_count == 0) return -1;
  char norm_user_host[MAX_MASK_LEN];
  strip_ident_tilde(user_host, norm_user_host, sizeof(norm_user_host));
  for (int i = 0; i < state->trusted_bot_count; i++) {
    char norm_hostmask[MAX_MASK_LEN];
    strip_ident_tilde(state->trusted_bots[i].mask, norm_hostmask,
                      sizeof(norm_hostmask));
    if (auth_wildcard_match(norm_hostmask, norm_user_host))
      return i;
  }
  return -1;
}

trusted_bot_t *auth_trusted_bot_by_host(bot_state_t *state,
                                        const char *user_host) {
  int i = trusted_bot_index_by_host(state, user_host);
  return i < 0 ? NULL : &state->trusted_bots[i];
}

trusted_bot_t *auth_trusted_bot_by_uuid(bot_state_t *state, const char *uuid) {
  if (!uuid || !uuid[0]) return NULL;
  for (int i = 0; i < state->trusted_bot_count; i++)
    if (strcmp(state->trusted_bots[i].uuid, uuid) == 0)
      return &state->trusted_bots[i];
  return NULL;
}

void auth_trusted_bot_nick(const trusted_bot_t *tb, char out[MAX_NICK]) {
  size_t n = strcspn(tb->mask, "!");
  if (n >= MAX_NICK) n = MAX_NICK - 1;
  memcpy(out, tb->mask, n);
  out[n] = '\0';
}

const char *bot_who(const bot_state_t *state, char kind, const char *uuid) {
  static _Thread_local char slots[BOT_WHO_SLOTS][BOT_WHO_MAX];
  static _Thread_local int next;
  next = (next + 1) % BOT_WHO_SLOTS;
  char *out = slots[next];
  const char *word = kind == 'u' ? "user" : "bot";
  char name[MAX_NICK > 64 ? MAX_NICK : 64] = "";
  if (uuid && uuid[0] && kind == 'b') {
    for (int i = 0; i < state->trusted_bot_count; i++)
      if (strcmp(state->trusted_bots[i].uuid, uuid) == 0) {
        auth_trusted_bot_nick(&state->trusted_bots[i], name);
        break;
      }
  } else if (uuid && uuid[0] && kind == 'u') {
    for (int i = 0; i < state->user_record_count; i++)
      if (strcmp(state->user_records[i].uuid, uuid) == 0) {
        word = state->user_records[i].type == 'a' ? "admin" : "oper";
        snprintf(name, sizeof(name), "%s", state->user_records[i].name);
        break;
      }
  }
  snprintf(out, BOT_WHO_MAX, "%s %.63s (%.63s)", word, name[0] ? name : "?",
           uuid && uuid[0] ? uuid : "?");
  /* names come from the hub: no control byte reaches a log line through one */
  for (char *q = out; *q; q++)
    if ((unsigned char)*q < 0x20 || *q == 0x7f) *q = '_';
  return out;
}

trusted_bot_t *auth_trusted_bot_by_nick(bot_state_t *state, const char *nick) {
  if (!nick || !nick[0]) return NULL;
  for (int i = 0; i < state->trusted_bot_count; i++) {
    char bnick[MAX_NICK];
    auth_trusted_bot_nick(&state->trusted_bots[i], bnick);
    if (strcasecmp(bnick, nick) == 0) return &state->trusted_bots[i];
  }
  return NULL;
}

// auth_is_trusted_bot: boolean wrapper over auth_trusted_bot_by_host.  On a
// match, if uuid_out is non-NULL, also fills in the matched entry's UUID.
bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host,
                         char *uuid_out, size_t uuid_out_size) {
  if (uuid_out && uuid_out_size > 0) uuid_out[0] = '\0';
  int i = trusted_bot_index_by_host(state, user_host);
  if (i < 0) return false;
  if (uuid_out && uuid_out_size > 0)
    snprintf(uuid_out, uuid_out_size, "%s", state->trusted_bots[i].uuid);
  return true;
}

/* A user whose standing counts in chan (user_flags plan §6, U12): every
 * active admin everywhere (network staff, whatever their flags); an oper in
 * the channels it is bound to, or everywhere with "*".  chan NULL = anywhere:
 * an oper with any live binding (bot flood exemption is per bot, not per
 * channel). */
static bool user_counts_in(const bot_state_t *state, const user_record_t *ur,
                           const char *chan) {
  if (!ur->is_active) return false;
  if (ur->type == 'a') return true;
  if (!chan) return access_user_chan_count(state, ur->uuid, NULL) > 0;
  return access_user_chan_ok(state, ur->uuid, chan);
}

/* modes.md §1: "authorised" = matches a trusted-bot mask, or an active
 * usermask of an active admin/oper -- an oper only in its channels (plan
 * §6).  The user record need not hold a key: what matters is the
 * operator's standing, not whether they can sign ~A2. */
bool auth_is_authorised(const bot_state_t *state, const char *nuh, const char *chan) {
  if (!state || !nuh || !nuh[0])
    return false;
  if (auth_is_trusted_bot(state, nuh, NULL, 0))
    return true;
  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *mr = &state->mask_records[i];
    if (!mr->is_active || mr->mask[0] == '\0')
      continue;
    if (!auth_wildcard_match(mr->mask, nuh))
      continue;
    for (int j = 0; j < state->user_record_count; j++) {
      const user_record_t *ur = &state->user_records[j];
      if (strcmp(ur->uuid, mr->uuid) == 0 && user_counts_in(state, ur, chan))
        return true;
    }
  }
  return false;
}

/* §6.2 step 2: refuse a ban mask that could hit a bot or an operator who is
 * not in the channel right now.  Pattern-vs-pattern, so '*' on either side
 * is taken at its widest. */
bool auth_mask_overlaps_authorised(const bot_state_t *state, const char *mask,
                                   const char *chan, char *who, size_t who_size) {
  if (who && who_size)
    who[0] = '\0';
  if (!state || !mask)
    return true; /* fail closed */
  /* matching drops a leading '~' of the ident (strip_ident_tilde), so the
   * overlap test does too, on both sides */
  char nmask[MAX_MASK_LEN], nother[MAX_MASK_LEN];
  strip_ident_tilde(mask, nmask, sizeof(nmask));
  for (int i = 0; i < state->trusted_bot_count; i++) {
    strip_ident_tilde(state->trusted_bots[i].mask, nother, sizeof(nother));
    if (hostmask_overlap(nmask, nother)) {
      if (who && who_size)
        snprintf(who, who_size, "bot %s", state->trusted_bots[i].mask);
      return true;
    }
  }
  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *mr = &state->mask_records[i];
    if (!mr->is_active || mr->mask[0] == '\0')
      continue;
    strip_ident_tilde(mr->mask, nother, sizeof(nother));
    if (!hostmask_overlap(nmask, nother))
      continue;
    for (int j = 0; j < state->user_record_count; j++) {
      const user_record_t *ur = &state->user_records[j];
      if (strcmp(ur->uuid, mr->uuid) == 0 && user_counts_in(state, ur, chan)) {
        if (who && who_size)
          snprintf(who, who_size, "user %s", ur->name);
        return true;
      }
    }
  }
  return false;
}
