#include <openssl/sha.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
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

bool auth_check_hostmask(const bot_state_t *state, const char *user_host) {
  log_message(L_DEBUG, state, "[AUTH_CHECK] Checking user: %s\n", user_host);

  bool is_explicitly_allowed = false;
  bool is_explicitly_ignored = false;

  if (state->ignored_default_mask[0] != '\0') {
    if (wildcard_match(state->ignored_default_mask, user_host)) {
      is_explicitly_ignored = true;
    }
  }

  for (int i = 0; i < state->mask_count; i++) {
    // [UPDATED] Check .mask field of struct
    if (state->auth_masks[i].mask[0] == '\0') continue; 

    log_message(L_DEBUG, state, "[AUTH_CHECK] Comparing against: %s\n", state->auth_masks[i].mask);

    if (wildcard_match(state->auth_masks[i].mask, user_host)) {
      log_message(L_DEBUG, state, "[AUTH_CHECK] MATCH FOUND at index %d.\n", i);
      is_explicitly_allowed = true;
      break;
    }
  }

  if (is_explicitly_allowed) return true;
  if (is_explicitly_ignored) return false;

  log_message(L_DEBUG, state, "[AUTH_CHECK] No admin match found.\n");
  return false;
}

bool auth_verify_op_command(bot_state_t *state, const char *user_host,
                            const char *nonce_str, const char *hash_attempt) {
  log_message(L_DEBUG, state, "[OP_CHECK] Checking User: %s | Nonce: %s\n",
              user_host, nonce_str);

  for (int i = 0; i < state->op_mask_count; i++) {
    log_message(L_DEBUG, state, "[OP_CHECK] Compare vs Mask: %s\n",
                state->op_masks[i].mask);

    if (wildcard_match(state->op_masks[i].mask, user_host)) {
      log_message(L_DEBUG, state, "[OP_CHECK] Mask MATCH! Verifying password...\n");

      if (auth_verify_password(state, nonce_str, hash_attempt, state->op_masks[i].password)) {
        log_message(L_DEBUG, state, "[OP_CHECK] Password MATCH. Authorized.\n");
        return true;
      } else {
        log_message(L_DEBUG, state, "[OP_CHECK] Password FAIL.\n");

        char to_hash[512];
        char hex[65];
        unsigned char raw[SHA256_DIGEST_LENGTH];
        uint64_t nonce = strtoull(nonce_str, NULL, 10);
        long min = time(NULL) / 60;

        snprintf(to_hash, sizeof(to_hash), "%s:%ld:%llu",
                 state->op_masks[i].password, min, (unsigned long long)nonce);
        SHA256((unsigned char *)to_hash, strlen(to_hash), raw);
        int offset = 0;
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[j]);

        log_message(L_DEBUG, state, "[OP_CHECK] \n   EXPECTED: %s\n   RECEIVED: %s\n",
                    hex, hash_attempt);
      }
    }
  }

  log_message(L_DEBUG, state, "[OP_CHECK] No matching op masks found (or all failed).\n");
  return false;
}

bool auth_verify_password(bot_state_t *state, const char *nonce_str,
                          const char *hash_attempt, const char *stored_password) {
  if (!nonce_str || !hash_attempt || !stored_password) {
      log_message(L_DEBUG, state, "[DEBUG_AUTH] FAIL: Null inputs.\n");
      return false;
  }

  uint64_t nonce = strtoull(nonce_str, NULL, 10);

  for (int i = 0; i < MAX_SEEN_HASHES; i++) {
      if (state->admin_nonces[i] == nonce) {
          log_message(L_DEBUG, state, "[DEBUG_AUTH] FAIL: Replay detected (Nonce %" PRIu64 ").\n", nonce);
          return false;
      }
  }

  char to_hash[512];
  char hex[65];
  unsigned char raw[SHA256_DIGEST_LENGTH];

  long min = (long)(time(NULL) / 60);

  // Time Window 1 (Current Minute)
  snprintf(to_hash, sizeof(to_hash), "%s:%ld:%" PRIu64,
           stored_password, min, nonce);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);

  int offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }

  log_message(L_DEBUG, state, "[DEBUG_AUTH] Check 1 (Min %ld):\n   Calc: %s\n   Recv: %s\n",
              min, hex, hash_attempt);

  if (strcmp(hash_attempt, hex) == 0) {
      state->admin_nonces[state->admin_nonce_idx] = nonce;
      state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
      return true;
  }

  // Time Window 2 (Previous Minute - allowing clock skew/lag)
  snprintf(to_hash, sizeof(to_hash), "%s:%ld:%" PRIu64,
           stored_password, (min - 1), nonce);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);

  offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }

  log_message(L_DEBUG, state, "[DEBUG_AUTH] Check 2 (Min %ld):\n   Calc: %s\n   Recv: %s\n",
              (min - 1), hex, hash_attempt);

  if (strcmp(hash_attempt, hex) == 0) {
      state->admin_nonces[state->admin_nonce_idx] = nonce;
      state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
      return true;
  }

  return false;
}

bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host) {
  if (state->trusted_bot_count == 0) return false;

  for (int i = 0; i < state->trusted_bot_count; i++) {
    // Trusted bots list is still char*, so no struct access needed here
    if (wildcard_match(state->trusted_bots[i], user_host)) {
      return true;
    }
  }
  return false;
}
