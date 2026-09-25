#include <string.h>
#include <strings.h>
#include <time.h> // Ensure time() is available

#include "bot.h"

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
trusted_bot_t *auth_trusted_bot_by_host(bot_state_t *state,
                                        const char *user_host) {
  if (state->trusted_bot_count == 0) return NULL;
  char norm_user_host[MAX_MASK_LEN];
  strip_ident_tilde(user_host, norm_user_host, sizeof(norm_user_host));
  for (int i = 0; i < state->trusted_bot_count; i++) {
    char norm_hostmask[MAX_MASK_LEN];
    strip_ident_tilde(state->trusted_bots[i].mask, norm_hostmask,
                      sizeof(norm_hostmask));
    if (auth_wildcard_match(norm_hostmask, norm_user_host))
      return &state->trusted_bots[i];
  }
  return NULL;
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
  trusted_bot_t *tb =
      auth_trusted_bot_by_host((bot_state_t *)state, user_host);
  if (!tb) return false;
  if (uuid_out && uuid_out_size > 0)
    snprintf(uuid_out, uuid_out_size, "%s", tb->uuid);
  return true;
}
