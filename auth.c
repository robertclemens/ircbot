#include <openssl/sha.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

static bool wildcard_match(const char *pattern, const char *text) {
  const char *p = pattern, *t = text;
  const char *last_wildcard = NULL, *last_text_for_wildcard = NULL;

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
  bool is_explicitly_allowed = false;
  bool is_explicitly_ignored = false;

  if (state->ignored_default_mask[0] != '\0') {
    if (wildcard_match(state->ignored_default_mask, user_host)) {
      is_explicitly_ignored = true;
    }
  }
  for (int i = 0; i < state->mask_count; i++) {
    if (wildcard_match(state->auth_masks[i], user_host)) {
      is_explicitly_allowed = true;
      break;
    }
  }
  if (is_explicitly_allowed) {
    return true;
  }
  if (is_explicitly_ignored) {
    return false;
  }
  return true;
}

bool auth_verify_op_command(const bot_state_t *state, const char *user_host,
                            const char *hash_attempt) {
  for (int i = 0; i < state->op_mask_count; i++) {
    if (wildcard_match(state->op_masks[i].mask, user_host)) {
      if (auth_verify_password(hash_attempt, state->op_masks[i].password)) {
        return true;
      }
    }
  }
  return false;
}
bool auth_verify_password(const char *hash_attempt,
                          const char *stored_password) {
  if (!hash_attempt || !stored_password || stored_password[0] == '\0')
    return false;

  char to_hash[256];
  char hex[65];
  unsigned char raw[SHA256_DIGEST_LENGTH];
  long min = time(NULL) / 60;

  snprintf(to_hash, sizeof(to_hash), "%s:%ld", stored_password, min);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);

  int offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }
  if (strcmp(hash_attempt, hex) == 0) return true;
  snprintf(to_hash, sizeof(to_hash), "%s:%ld", stored_password, min - 1);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw);
  offset = 0;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    offset += snprintf(hex + offset, sizeof(hex) - offset, "%02x", raw[i]);
  }
  if (strcmp(hash_attempt, hex) == 0) return true;

  return false;
}
