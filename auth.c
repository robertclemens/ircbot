#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
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

bool auth_verify_password(bot_state_t *state, const char *nonce_str,
                          const char *hash_attempt,
                          const char *stored_password) {
  if (!nonce_str || !hash_attempt || !stored_password) {
    log_message(L_DEBUG, state, "[DEBUG_AUTH] FAIL: Null inputs.\n");
    return false;
  }

  uint64_t nonce = strtoull(nonce_str, NULL, 10);

  for (int i = 0; i < MAX_SEEN_HASHES; i++) {
    if (state->admin_nonces[i] == nonce) {
      log_message(L_DEBUG, state,
                  "[DEBUG_AUTH] FAIL: Replay detected (Nonce %" PRIu64 ").\n",
                  nonce);
      return false;
    }
  }

  char to_hash[512];
  char hex[65];
  unsigned char raw[SHA256_DIGEST_LENGTH];

  long min = (long)(time(NULL) / 60);

  // Time Window 1 (Current Minute)
  snprintf(to_hash, sizeof(to_hash), "%s:%ld:%" PRIu64, stored_password, min,
           nonce);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);

  int offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }

  log_message(L_DEBUG, state,
              "[DEBUG_AUTH] Check 1 (Min %ld)\n", min);

  if (strlen(hash_attempt) == 64 &&
      CRYPTO_memcmp(hash_attempt, hex, 64) == 0) {
    state->admin_nonces[state->admin_nonce_idx] = nonce;
    state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
    OPENSSL_cleanse(to_hash, sizeof(to_hash));
    return true;
  }

  // Time Window 2 (Previous Minute - allowing clock skew/lag)
  snprintf(to_hash, sizeof(to_hash), "%s:%ld:%" PRIu64, stored_password,
           (min - 1), nonce);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);

  offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }

  log_message(L_DEBUG, state,
              "[DEBUG_AUTH] Check 2 (Min %ld)\n", (min - 1));

  if (strlen(hash_attempt) == 64 &&
      CRYPTO_memcmp(hash_attempt, hex, 64) == 0) {
    state->admin_nonces[state->admin_nonce_idx] = nonce;
    state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
    OPENSSL_cleanse(to_hash, sizeof(to_hash));
    return true;
  }

  OPENSSL_cleanse(to_hash, sizeof(to_hash));
  return false;
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

/* auth_verify_password_record: same HMAC check as auth_verify_password but
 * uses user_record_t.password instead of a global bot_pass. */
bool auth_verify_password_record(const user_record_t *user,
                                 const char *nonce_str,
                                 const char *hash_attempt) {
  if (!user || !nonce_str || !hash_attempt) return false;
  /* Re-use the existing auth_verify_password by casting away const on state
   * just for nonce cache tracking — we pass NULL state to skip cache, then
   * do manual replay check via admin_nonces in the caller. */
  /* Build the expected hash directly so we don't need a full state pointer. */
  uint64_t nonce = strtoull(nonce_str, NULL, 10);
  long min = (long)(time(NULL) / 60);

  for (int window = 0; window <= 1; window++) {
    char to_hash[512];
    char hex[65];
    unsigned char raw[SHA256_DIGEST_LENGTH];
    snprintf(to_hash, sizeof(to_hash), "%s:%ld:%" PRIu64,
             user->password, min - window, nonce);
    SHA256((unsigned char *)to_hash, strlen(to_hash), raw);
    int off = 0;
    for (int k = 0; k < SHA256_DIGEST_LENGTH; k++)
      off += snprintf(hex + off, sizeof(hex) - off, "%02x", raw[k]);
    OPENSSL_cleanse(to_hash, sizeof(to_hash));
    if (strlen(hash_attempt) == 64 &&
        CRYPTO_memcmp(hash_attempt, hex, 64) == 0)
      return true;
  }
  return false;
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

bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host) {
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
        return true;
      }
    }
  }
  return false;
}
