#include <string.h>
#include <strings.h>
#include <time.h> // Ensure time() is available

#include "bot.h"

static bool wildcard_match(const char *pattern, const char *text) {
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

/* auth_find_user: find the user_record_t whose usermask matches user_host.
 * Updates last_used on the matching mask and last_seen on the user record.
 * Sets state->config_dirty so the timestamps are persisted on next flush. */
user_record_t *auth_find_user(bot_state_t *state, const char *user_host,
                              time_t now) {
  for (int i = 0; i < state->mask_record_count; i++) {
    mask_record_t *mr = &state->mask_records[i];
    if (!mr->is_active || mr->mask[0] == '\0') continue;

    if (wildcard_match(mr->mask, user_host)) {
      /* Find the owning user record */
      for (int j = 0; j < state->user_record_count; j++) {
        user_record_t *ur = &state->user_records[j];
        if (!ur->is_active) continue;
        if (strcmp(ur->uuid, mr->uuid) != 0) continue;
        /* Match — update timestamps */
        mr->last_used  = now;
        ur->last_seen  = now;
        state->config_dirty = true;
        log_message(L_DEBUG, state,
                    "[AUTH] mask %s matched user %s (%c)\n",
                    mr->mask, ur->name, ur->type);
        return ur;
      }
    }
  }
  log_message(L_DEBUG, state, "[AUTH] no mask matched %s\n", user_host);
  return NULL;
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

// auth_is_trusted_bot: wildcard-match user_host against trusted_bots[]
// hostmasks. On a match, if uuid_out is non-NULL, also fills in the
// matched entry's UUID (hostmask|uuid|timestamp format) so callers that
// need to bind the sender's identity (e.g. GCM AAD) don't have to
// re-implement this lookup.
bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host,
                         char *uuid_out, size_t uuid_out_size) {
  if (uuid_out && uuid_out_size > 0) uuid_out[0] = '\0';
  if (state->trusted_bot_count == 0)
    return false;

  char norm_user_host[MAX_MASK_LEN];
  strip_ident_tilde(user_host, norm_user_host, sizeof(norm_user_host));

  for (int i = 0; i < state->trusted_bot_count; i++) {
    // Extract hostmask from format: hostmask|uuid|timestamp
    // or just hostmask for legacy entries
    char hostmask[MAX_MASK_LEN];
    if (sscanf(state->trusted_bots[i], "%255[^|]", hostmask) == 1) {
      char norm_hostmask[MAX_MASK_LEN];
      strip_ident_tilde(hostmask, norm_hostmask, sizeof(norm_hostmask));
      if (wildcard_match(norm_hostmask, norm_user_host)) {
        if (uuid_out && uuid_out_size > 0) {
          char uuid[64] = "";
          sscanf(state->trusted_bots[i], "%*255[^|]|%63[^|]", uuid);
          snprintf(uuid_out, uuid_out_size, "%s", uuid);
        }
        return true;
      }
    }
  }
  return false;
}
