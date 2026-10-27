#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bot.h"

/* Split s on '|' into at most max fields (pointers + lengths into s, no
 * copies).  Returns the field count; a trailing '|' yields an empty field. */
static int split_fields(const char *s, const char **f, size_t *fl, int max) {
  int n = 0;
  while (n < max) {
    const char *bar = strchr(s, '|');
    f[n] = s;
    fl[n] = bar ? (size_t)(bar - s) : strlen(s);
    n++;
    if (!bar) break;
    s = bar + 1;
  }
  return n;
}

static bool is_uuid_field(const char *s, size_t len) {
  if (len != 36) return false;
  for (size_t i = 0; i < 36; i++) {
    char c = s[i];
    bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
    if (dash ? c != '-'
             : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F')))
      return false;
  }
  return true;
}

/* Decode a key-shaped field; false unless it is exactly a valid key. */
static bool field_pubkey(const char *f, size_t fl, char out_b64[COMBINED_KEY_B64 + 1]) {
  unsigned char raw[HUB_KEY_RAW_LEN];
  out_b64[0] = '\0';
  if (fl != COMBINED_KEY_B64) return false;
  memcpy(out_b64, f, COMBINED_KEY_B64);
  out_b64[COMBINED_KEY_B64] = '\0';
  bool ok = crypto_pubkey_b64_decode(out_b64, raw);
  if (!ok) out_b64[0] = '\0';
  return ok;
}

/* a|/o| body codec (irchub/docs/passwordless.md §3.1):
 *   uuid|name|pubkey|add/del|last_seen|ts|<reserved, empty>
 * pubkey may be empty (a user not given a key yet); anything else that is not
 * a valid key refuses the line.  Also used by hub_client.c for hub-sent
 * records. */
bool config_parse_user_line(const char *data, user_line_t *out) {
  const char *f[8];
  size_t fl[8];
  memset(out, 0, sizeof(*out));
  int nf = split_fields(data, f, fl, 8);
  if (nf < 6 || !is_uuid_field(f[0], fl[0])) return false;
  if (fl[1] == 0 || fl[1] >= sizeof(out->name)) return false;
  memcpy(out->uuid, f[0], 36);
  memcpy(out->name, f[1], fl[1]);
  if (fl[2] > 0) {
    if (!field_pubkey(f[2], fl[2], out->pubkey_b64)) return false;
    out->has_pubkey = true;
  }
  out->is_active = (fl[3] == 3 && strncmp(f[3], "add", 3) == 0);
  out->last_seen = (time_t)strtoll(f[4], NULL, 10);
  out->timestamp = (time_t)strtoll(f[5], NULL, 10);
  return true;
}

/* Serialize one user record as a full "a|...\n" / "o|...\n" line. */
int config_format_user_line(const user_record_t *u, char *buf, size_t len) {
  return snprintf(buf, len, "%c|%s|%s|%s|%s|%lld|%lld|\n", u->type, u->uuid,
                  u->name, u->has_pubkey ? u->pubkey_b64 : "",
                  u->is_active ? "add" : "del", (long long)u->last_seen,
                  (long long)u->timestamp);
}

/* b| body codec (passwordless.md §3.2):
 *   mask|uuid|pubkey|ts       (pubkey may be empty)
 * Oversized fields are refused rather than truncated: a clipped mask or uuid
 * would silently mis-key every later match. */
bool config_parse_bot_line(const char *data, trusted_bot_t *out) {
  const char *f[5];
  size_t fl[5];
  memset(out, 0, sizeof(*out));
  int nf = split_fields(data, f, fl, 5);
  if (nf < 4 || fl[0] == 0 || fl[0] >= sizeof(out->mask)) return false;
  memcpy(out->mask, f[0], fl[0]);
  if (fl[1] >= sizeof(out->uuid)) return false;
  memcpy(out->uuid, f[1], fl[1]);
  char b64[COMBINED_KEY_B64 + 1];
  if (fl[2] > 0 && field_pubkey(f[2], fl[2], b64))
    out->has_pub = crypto_pubkey_b64_decode(b64, out->pub);
  out->ts = (time_t)strtoll(f[3], NULL, 10);
  return true;
}

/* Serialize one trusted bot as a full "b|...\n" line (new format). */
int config_format_bot_line(const trusted_bot_t *tb, char *buf, size_t len) {
  char *pb = tb->has_pub ? base64_encode(tb->pub, HUB_KEY_RAW_LEN) : NULL;
  int n = snprintf(buf, len, "b|%s|%s|%s|%lld\n", tb->mask, tb->uuid,
                   pb ? pb : "", (long long)tb->ts);
  free(pb);
  return n;
}

static void gen_uuid_v4(char out[37]) {
  unsigned char r[16];
  if (RAND_bytes(r, sizeof(r)) != 1)
    handle_fatal_error("RAND_bytes failed generating a UUID");
  r[6] = (unsigned char)((r[6] & 0x0f) | 0x40);
  r[8] = (unsigned char)((r[8] & 0x3f) | 0x80);
  snprintf(out, 37,
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10],
           r[11], r[12], r[13], r[14], r[15]);
}

/* Set by -selftest: load and validate, never rewrite.  A staged build is
 * checked against the live config before it is installed, and must not
 * migrate that config out from under the build that is still running. */
bool g_config_readonly = false;

/* Review 23: the config key, derived once per process (the first load or
 * write) and reused.  A 600k-round PBKDF2 on every write froze the bot for
 * ~0.5 s, and any chanop toggling +k/-k could trigger one.  The key is bound
 * to the salt it was derived with, which every later write reuses under a
 * fresh IV.  A process has one password (the startup one), so nothing else
 * invalidates it; mlock'd like that password, wiped at shutdown. */
static struct {
  bool set;
  unsigned char salt[SALT_SIZE];
  unsigned char key[32];
} g_cfg_key;

static void cfg_key_keep(const unsigned char *salt, const unsigned char *key) {
  if (!g_cfg_key.set) mlock(&g_cfg_key, sizeof(g_cfg_key));
  memcpy(g_cfg_key.salt, salt, SALT_SIZE);
  memcpy(g_cfg_key.key, key, sizeof(g_cfg_key.key));
  g_cfg_key.set = true;
}

void config_key_forget(void) {
  secure_wipe(&g_cfg_key, sizeof(g_cfg_key));
}

bool config_load(bot_state_t *state, const char *password,
                 const char *filename) {
  struct stat cfg_st;
  if (stat(filename, &cfg_st) == 0 && (cfg_st.st_mode & 0177) != 0)
    log_message(L_INFO, state,
                "[CFG] WARN: %s has insecure permissions %04o — should be 0600\n",
                filename, (unsigned)(cfg_st.st_mode & 0777));
  FILE *in_file = fopen(filename, "rb");
  if (!in_file) {
    return false;
  }

  unsigned char salt[SALT_SIZE];
  if (fread(salt, 1, sizeof(salt), in_file) != sizeof(salt)) {
    log_message(L_INFO, state, "[CFG] Failed to read Salt from config.\n");
    fclose(in_file);
    return false;
  }

  unsigned char iv[GCM_IV_LEN];
  unsigned char tag[GCM_TAG_LEN];
  if (fread(iv, 1, sizeof(iv), in_file) != sizeof(iv) ||
      fread(tag, 1, sizeof(tag), in_file) != sizeof(tag)) {
    log_message(L_INFO, state, "[CFG] Failed to read IV/Tag from config.\n");
    fclose(in_file);
    return false;
  }

  fseek(in_file, 0, SEEK_END);
  long ciphertext_len = ftell(in_file) - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;
  fseek(in_file, SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);

  if (ciphertext_len <= 0 || ciphertext_len > MAX_CONFIG_SIZE) {
    log_message(L_INFO, state,
                "[CFG] Error: Config file is empty or too large (Max 1MB).\n");
    fclose(in_file);
    return false;
  }

  unsigned char *ciphertext = malloc((size_t)ciphertext_len);
  if (!ciphertext)
    handle_fatal_error("malloc failed for ciphertext");

  if (fread(ciphertext, 1, (size_t)ciphertext_len, in_file) != (size_t)ciphertext_len) {
    log_message(
        L_INFO, state,
        "[CFG] Error: Could not read the full contents of the config file.\n");
    fclose(in_file);
    free(ciphertext);
    return false;
  }
  fclose(in_file);

  unsigned char *plaintext = malloc((size_t)ciphertext_len + 1);
  if (!plaintext)
    handle_fatal_error("malloc failed for plaintext");
  int plaintext_len = 0;
  int len = 0;

  int final_rc = 0;
  unsigned char key[32];
  if (crypto_derive_config_key(password, salt, PBKDF2_ITERATIONS, key)) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
      int pl = 0, fl = 0;
      if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 1 &&
          EVP_DecryptUpdate(ctx, plaintext, &pl, ciphertext,
                            (int)ciphertext_len) == 1 &&
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) == 1 &&
          EVP_DecryptFinal_ex(ctx, plaintext + pl, &fl) > 0) {
        plaintext_len = pl;
        len = fl;
        final_rc = 1;
      } else {
        /* Unverified plaintext must not outlive a failed tag check. */
        secure_wipe(plaintext, (size_t)ciphertext_len);
      }
      EVP_CIPHER_CTX_free(ctx);
    }
  }
  if (final_rc > 0) cfg_key_keep(salt, key);
  secure_wipe(key, sizeof(key));
  free(ciphertext);
  if (final_rc <= 0) {
    log_message(L_INFO, state, "[CFG] Decryption failed (wrong password, or a "
                "config written before 2.5.0: run 2.5.0 once).\n");
    free(plaintext);
    return false;
  }

  if (final_rc > 0) {
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    // NEW: Pipe-delimited parser
    char *saveptr1;
    char *line = strtok_r((char *)plaintext, "\n", &saveptr1);

    while (line) {

      size_t line_sz = strlen(line);
      if (line_sz > 0 && line[line_sz - 1] == '\r')
        line[line_sz - 1] = '\0';

      if (strlen(line) < 2 || line[0] == '#') {
        line = strtok_r(NULL, "\n", &saveptr1);
        continue;
      }

      /* uf| / uc|: admin flags and oper channel bindings (access.c);
       * users load first in this file, records of a user that never loads
       * go with access_prune below */
      if (line[0] == 'u' && (line[1] == 'f' || line[1] == 'c') && line[2] == '|') {
        if (!access_ingest(state, line[1], line + 3, false, NULL))
          log_message(L_INFO, state, "[CFG] Ignoring invalid %.2s| line\n", line);
        line = strtok_r(NULL, "\n", &saveptr1);
        continue;
      }

      char type = line[0];

      if (line[1] != '|') {
        // Invalid format, skip
        line = strtok_r(NULL, "\n", &saveptr1);
        continue;
      }

      char *data = line + 2; // Skip "X|"

      switch (type) {
      case 'n': // Nickname (bot-specific)
        snprintf(state->target_nick, MAX_NICK, "%s", data);
        break;

      case 's': // Server (bot-specific)
        if (state->server_count < MAX_SERVERS) {
          state->server_list[state->server_count++] = strdup(data);
        }
        break;

      case 'c': // Channel (global, with timestamp)
      {
        char chan[MAX_CHAN], chan_key[MAX_KEY], op[16];
        long long ts_ll = 0;
        time_t ts = 0;

        // Parse: channel|key|add/del|timestamp
        int parsed =
            sscanf(data, "%64[^|]|%30[^|]|%15[^|]|%lld", chan, chan_key, op, &ts_ll);

        // Fallback for empty key: channel||add/del|timestamp
        if (parsed < 3) {
          parsed = sscanf(data, "%64[^|]||%15[^|]|%lld", chan, op, &ts_ll);
          chan_key[0] = '\0';
        }
        ts = (time_t)ts_ll;

        if (parsed >= 2) { // Need at least chan, op (key can be empty)
          // If fallback matched 3 items (chan, op, ts) or first matched 4
          // (chan,key,op,ts) Actually fallback matches 3 items. First matches 4
          // items. Adjust logic:

          /* Channel names match regardless of ASCII case (D39): a file that
           * holds both "#Chan" and "#chan" merges into one entry, the newest
           * stamp winning (the first writer's spelling is kept). */
          bool is_add = (strcmp(op, "del") != 0);
          time_t eff_ts = (ts > 0) ? ts : time(NULL);
          chan_t *c = channel_find(state, chan);
          if (c) {
            /* timestamp 0 = a C| line got here first (held unmanaged) */
            if (c->timestamp == 0 ||
                lww_accepts(eff_ts, is_add, c->timestamp, c->is_managed)) {
              snprintf(c->ckey, MAX_KEY, "%s", chan_key);
              c->is_managed = is_add;
              c->timestamp = eff_ts;
              if (!c->is_managed) {
                c->status = C_OUT;
                chan_learned_forget(c);
              }
              chan_key_refresh(c);
            }
          } else if ((c = channel_add(state, chan)) != NULL) {
            if (strlen(chan_key) > 0) {
              snprintf(c->ckey, MAX_KEY, "%s", chan_key);
            }
            c->is_managed = is_add;
            c->timestamp = eff_ts;
            chan_key_refresh(c);

            if (strlen(chan_key) > 0)
              state->chan_count++;

            // Don't join deleted channels
            if (!c->is_managed) {
              c->status = C_OUT;
            }
          }
        }
      } break;

      case 'm': // Usermask record: uuid|mask|add/del|last_used|ts
      {
        const char *f[5] = {0};
        size_t fl[5] = {0};
        if (split_fields(data, f, fl, 5) < 5 || !is_uuid_field(f[0], fl[0]) ||
            fl[1] == 0 || fl[1] >= MAX_MASK_LEN ||
            state->mask_record_count >= MAX_USER_MASKS)
          break;
        mask_record_t *m = &state->mask_records[state->mask_record_count++];
        memset(m, 0, sizeof(*m));
        memcpy(m->uuid, f[0], 36);
        memcpy(m->mask, f[1], fl[1]);
        m->is_active = (fl[2] == 3 && strncmp(f[2], "add", 3) == 0);
        m->last_used = (time_t)strtoll(f[3], NULL, 10);
        m->timestamp = (time_t)strtoll(f[4], NULL, 10);
      } break;

      case 'o': // Oper record  } config_parse_user_line
      case 'a': // Admin record }
      {
        if (state->user_record_count >= MAX_USER_RECORDS) break;
        user_line_t ul;
        if (!config_parse_user_line(data, &ul)) {
          log_message(L_INFO, state, "[CFG] Malformed %c| record ignored.\n",
                      type);
          break;
        }
        user_record_t *u = &state->user_records[state->user_record_count++];
        memset(u, 0, sizeof(*u));
        memcpy(u->uuid, ul.uuid, sizeof(u->uuid));
        memcpy(u->name, ul.name, sizeof(u->name));
        memcpy(u->pubkey_b64, ul.pubkey_b64, sizeof(u->pubkey_b64));
        u->has_pubkey = ul.has_pubkey;
        u->type = type;
        u->is_active = ul.is_active;
        u->last_seen = ul.last_seen;
        u->timestamp = ul.timestamp;
      } break;

      case 'b': // Trusted bot: b|mask|uuid|pubkey|ts
        if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
          trusted_bot_t tb;
          if (config_parse_bot_line(data, &tb))
            state->trusted_bots[state->trusted_bot_count++] = tb;
          else
            log_message(L_INFO, state,
                        "[CFG] Malformed or oversized b| line ignored.\n");
        }
        break;

      case 'l': { // Log level (bot-specific)
        int lt = atoi(data);
        state->log_type = (log_type_t)lt;
        break;
      }

      case 'L': { // Log file cap in bytes (bot-specific), clamped on load
        long cap = strtol(data, NULL, 10);
        if (cap < BOT_LOG_SIZE_MIN) cap = BOT_LOG_SIZE_MIN;
        if (cap > BOT_LOG_SIZE_MAX) cap = BOT_LOG_SIZE_MAX;
        state->log_max_size = cap;
        break;
      }

      case 'u': // User/ident (bot-specific)
        snprintf(state->user, sizeof(state->user), "%s", data);
        break;

      case 'g': // Gecos (bot-specific)
        snprintf(state->gecos, sizeof(state->gecos), "%s", data);
        break;

      case 'v': // Vhost (bot-specific)
        snprintf(state->vhost, sizeof(state->vhost), "%s", data);
        break;

      case 'h': /* Hub entry (bot-specific): h|<host:port>[|<pubkey_b64>]
                 * The optional pubkey is the hub's pinned Ed25519 public key,
                 * either 44-char base64 (raw 32 bytes) or 88-char base64
                 * (combined 64-byte Curve25519 pubkey — we take the first 32,
                 * matching hub_public.b64). A line with no pubkey leaves the
                 * hub unpinned: the bot will not link to it until one is set. */
        if (state->hub_count < MAX_SERVERS) {
          hub_entry_t *he = &state->hubs[state->hub_count];
          memset(he, 0, sizeof(*he));
          char *bar = strchr(data, '|');
          if (bar) {
            size_t al = (size_t)(bar - data);
            if (al >= sizeof(he->addr)) al = sizeof(he->addr) - 1;
            memcpy(he->addr, data, al);
            he->addr[al] = '\0';
            int dl = 0;
            unsigned char *dec = base64_decode(bar + 1, &dl);
            if (dec && (dl == 32 || dl == HUB_KEY_RAW_LEN)) {
              memcpy(he->ed_pub, dec, 32);
              he->ed_pub_set = true;
            } else {
              log_message(L_INFO, state,
                          "[CFG] Hub '%s' pubkey is not a valid Ed25519/"
                          "Curve25519 key — re-add with '+hub %s <pubkey>'.\n",
                          he->addr, he->addr);
            }
            if (dec) { secure_wipe(dec, (size_t)(dl > 0 ? dl : 0)); free(dec); }
          } else {
            snprintf(he->addr, sizeof(he->addr), "%s", data);
          }
          state->hub_count++;
        }
        break;

      case 'k': { // Hub key (Curve25519 combined: Ed25519 + X25519)
        int dec_len = 0;
        unsigned char *dec = base64_decode(data, &dec_len);
        if (dec && dec_len == 64) {
          snprintf(state->hub_key, sizeof(state->hub_key), "%s", data);
          memcpy(state->hub_key_raw, dec, 64);
        } else {
          log_message(L_INFO, state,
                      "[CFG] Bot key in config is not a valid 64-byte "
                      "Curve25519 key. Re-run 'ircbot -setup' "
                      "to regenerate the bot's identity.\n");
        }
        /* the decoded length, not 64: base64_decode allocates strlen(input),
         * so a short k| value left a smaller buffer than the wipe */
        if (dec) { if (dec_len > 0) secure_wipe(dec, (size_t)dec_len); free(dec); }
        break;
      }

      case 'i': // Bot UUID (bot-specific)
        snprintf(state->bot_uuid, sizeof(state->bot_uuid), "%s", data);
        break;

      case 'D': /* D|1: user/mask changes made while the hub was unreachable
                 * are still to be pushed (admin_delta_pending).  A D| line
                 * with fields (D|<modes>|<settings>|<ts>) is the network
                 * defaults record; the two never share a shape. */
        if (strchr(data, '|') == NULL)
          state->admin_delta_pending = (strcmp(data, "1") == 0);
        else
          chancfg_apply_d_line(state, data);
        break;

      case 'C': /* C|#chan|<modes>|<settings>|add/del|ts (modes.md) */
        chancfg_apply_c_line(state, data);
        break;

      case 'K': /* K|#chan|key|modes|ts: learned on IRC, after its c| line */
        chan_learned_ingest(state, data);
        break;

      case 'B': /* B|<#chan|*>|<mask>|<expires>|<flags>|<setter>|<reason>|op|ts */
        chancfg_apply_b_line(state, data);
        break;

      case 'O': /* Network options string: O|<letters>|<timestamp>
                 * (Stored under the 'O' line — single capital letter so it
                 * cannot collide with the existing 'o' oper record line.) */
      {
        char flags[MAX_OPT_FLAGS + 1] = {0};
        long long ts = 0;
        /* "O||<ts>" is a persisted clear; %[^|] cannot match an empty field. */
        bool ok = (data[0] == '|')
                      ? (sscanf(data + 1, "%lld", &ts) == 1)
                      : (sscanf(data, "%32[^|]|%lld", flags, &ts) >= 1);
        if (ok) {
          /* Sanitize: keep only [a-zA-Z0-9] */
          int w = 0;
          for (int i = 0; flags[i] && w < MAX_OPT_FLAGS; i++) {
            char c = flags[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9'))
              state->opt_flags[w++] = c;
          }
          state->opt_flags[w] = '\0';
          state->opt_flags_ts = (ts > 0) ? (time_t)ts : time(NULL);
        }
      } break;
      }

      line = strtok_r(NULL, "\n", &saveptr1);
    }
  }

  secure_wipe(plaintext, (size_t)plaintext_len);
  free(plaintext);

  /* Identity key.  Standalone configs from before bots had keys carry no k|;
   * the ~A2 / ~B2 transports need one, so mint it here.  A hub-managed bot
   * without a key cannot reach its hub either and must re-run -setup (a new
   * identity would need registering on the hub), so it is only reported. */
  bool identity_minted = false;
  if (state->hub_key[0] == '\0' && state->hub_count == 0) {
    unsigned char priv[HUB_KEY_RAW_LEN], pub[HUB_KEY_RAW_LEN];
    char *pb = NULL;
    if (crypto_generate_combined_keypair(priv, pub) &&
        (pb = base64_encode(priv, HUB_KEY_RAW_LEN)) != NULL &&
        strlen(pb) < sizeof(state->hub_key)) {
      snprintf(state->hub_key, sizeof(state->hub_key), "%s", pb);
      memcpy(state->hub_key_raw, priv, HUB_KEY_RAW_LEN);
      identity_minted = true;
    }
    if (pb) { secure_wipe(pb, strlen(pb)); free(pb); }
    secure_wipe(priv, sizeof(priv));
    if (!identity_minted)
      log_message(L_INFO, state, "[CFG] Could not generate an identity key.\n");
  }
  if (state->bot_uuid[0] == '\0' && state->hub_count == 0) {
    gen_uuid_v4(state->bot_uuid);
    identity_minted = true;
  }
  if (!bot_self_pub_refresh(state)) {
    log_message(L_INFO, state,
                "[CFG] No usable identity key (k|): admin commands and "
                "bot-to-bot messages cannot be decrypted. Re-run -setup.\n");
  } else if (identity_minted) {
    char *pb = base64_encode(state->self_pub, HUB_KEY_RAW_LEN);
    char fp[KEY_FP_LEN + 1];
    crypto_key_fingerprint(state->self_pub, fp);
    fprintf(stderr, "[CFG] Generated this bot's identity key. Public key: %s "
                    "(fp %s)\n", pb ? pb : "?", fp);
    log_message(L_INFO, state, "[CFG] Generated identity key, fp %s\n", fp);
    free(pb);
  }

  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *u = &state->user_records[i];
    if (u->is_active && !u->has_pubkey)
      log_message(L_INFO, state,
                  "[CFG] %s '%s' has no public key and cannot authenticate "
                  "until given one (chkey, or the hub console's 'userkey' "
                  "key').\n", u->type == 'a' ? "Admin" : "Oper", u->name);
  }

  /* Flags / bindings: drop those with no user, then give every user that
   * has none what they could do before flags (admins +a, opers *). */
  int access_before = state->uflag_record_count + state->uchan_record_count;
  access_prune(state);
  bool access_changed =
      state->uflag_record_count + state->uchan_record_count != access_before;
  access_changed |= access_migrate(state) > 0;

  /* Rewrite once if anything above changed the on-disk shape. */
  if ((identity_minted || access_changed) &&
      !g_config_readonly)
    config_write(state, password);

  // Validation changed
  if (state->target_nick[0] == '\0' || state->server_count == 0 ||
      state->user[0] == '\0') {
    log_message(L_INFO, state,
                "[CFG] Config file is missing required fields (Nick, Server, "
                "or Ident).\n");
    return false;
  }
  return true;
}

/* Serialize state to the encrypted config file on disk.
 * Does NOT push to the hub — callers that want a push call config_write(). */
static void config_write_file(const bot_state_t *state, const char *password) {
  if (state->retired) return;   /* wiped on the hub's order: stays gone */
  if (strlen(password) >= MAX_PASS)
    return;

  /* Heap, sized to the load limit: the serialized config holds the k| private
   * key, so it is wiped before free, and a config that does not fit is not
   * written at all (a truncated write would silently drop records — keep the
   * old file instead). */
  const int cap = MAX_CONFIG_SIZE;
  char *plaintext_overrides = calloc(1, (size_t)cap);
  if (!plaintext_overrides) {
    fprintf(stderr, "[CFG] Out of memory serializing config; not written.\n");
    return;
  }
  int offset = 0;
  int remaining = cap;
  int written;
  bool overflow = false;

#define CFG_WRITE(...)                                          \
  do {                                                          \
    written = snprintf(plaintext_overrides + offset,            \
                       (size_t)remaining, __VA_ARGS__);         \
    if (written > 0 && written < remaining) {                   \
      offset += written; remaining -= written;                  \
    } else if (written != 0) {                                  \
      overflow = true;                                          \
    }                                                           \
  } while (0)

  CFG_WRITE("n|%s\n", state->target_nick);

  for (int i = 0; i < state->server_count; i++)
    CFG_WRITE("s|%s\n", state->server_list[i]);

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    /* A channel known only from its C| line (no c| yet) has no record of
     * its own to write. */
    if (c->timestamp == 0 && !c->is_managed)
      continue;
    CFG_WRITE("c|%s|%s|%s|%lld\n",
              c->name, c->ckey, c->is_managed ? "add" : "del", (long long)c->timestamp);
  }
  /* K|: what this bot saw on IRC, after every c| it needs at load. */
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    char ll[MAX_CHAN + MAX_KEY + 48];
    if (c->is_managed && c->l_ts > 0 && chan_format_l(c, ll, sizeof(ll)) > 0)
      CFG_WRITE("%s", ll);
    secure_wipe(ll, sizeof(ll));
  }

  /* modes.md records: per-channel settings, network defaults, bans.  Raw
   * settings text goes back out unchanged, unknown names included. */
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    char cl[C_LINE_MAX + 2];
    int cn = chancfg_format_c_line(c, cl, sizeof(cl));
    if (cn < 0) { overflow = true; break; }
    if (cn > 0) CFG_WRITE("%s", cl);
  }
  {
    char dl[D_LINE_MAX + 2];
    int dn = chancfg_format_d_line(state, dl, sizeof(dl));
    if (dn < 0) overflow = true;
    else if (dn > 0) CFG_WRITE("%s", dl);
  }
  for (int i = 0; i < state->cfg_ban_count; i++) {
    char bl[B_LINE_MAX + 2];
    int bn = chancfg_format_b_line(&state->cfg_bans[i], bl, sizeof(bl));
    if (bn <= 0) { overflow = true; break; }
    CFG_WRITE("%s", bl);
  }

  for (int i = 0; i < state->user_record_count; i++) {
    char uline[CFG_USER_LINE_MAX];
    int ul = config_format_user_line(&state->user_records[i], uline,
                                     sizeof(uline));
    if (ul <= 0 || ul >= (int)sizeof(uline)) { overflow = true; break; }
    CFG_WRITE("%s", uline);
  }

  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *m = &state->mask_records[i];
    CFG_WRITE("m|%s|%s|%s|%lld|%lld\n",
              m->uuid, m->mask, m->is_active ? "add" : "del",
              (long long)m->last_used, (long long)m->timestamp);
  }

  /* admin flags and oper channel bindings, after the users they name */
  for (int i = 0; i < state->uflag_record_count && !overflow; i++) {
    char l[CFG_UF_LINE_MAX];
    int w = access_format_uflag(&state->uflag_records[i], l, sizeof(l));
    if (w <= 0 || w >= (int)sizeof(l)) { overflow = true; break; }
    CFG_WRITE("%s", l);
  }
  for (int i = 0; i < state->uchan_record_count && !overflow; i++) {
    char l[CFG_UC_LINE_MAX];
    int w = access_format_uchan(&state->uchan_records[i], l, sizeof(l));
    if (w <= 0 || w >= (int)sizeof(l)) { overflow = true; break; }
    CFG_WRITE("%s", l);
  }

  for (int i = 0; i < state->trusted_bot_count; i++) {
    char bline[CFG_BLINE_MAX];
    int bl = config_format_bot_line(&state->trusted_bots[i], bline,
                                    sizeof(bline));
    if (bl <= 0 || bl >= (int)sizeof(bline)) { overflow = true; break; }
    CFG_WRITE("%s", bline);
  }

  if (state->log_type != DEFAULT_LOG_LEVEL)
    CFG_WRITE("l|%d\n", (int)state->log_type);
  /* 0 is a state that never ran state_init (the setup wizard): default. */
  if (state->log_max_size > 0 && state->log_max_size != BOT_LOG_FILE_SIZE)
    CFG_WRITE("L|%ld\n", state->log_max_size);

  CFG_WRITE("u|%s\n", state->user);
  CFG_WRITE("g|%s\n", state->gecos);

  if (state->vhost[0] != '\0')
    CFG_WRITE("v|%s\n", state->vhost);

  /* Per-hub entries: h|<host:port>[|<pinned-pubkey-b64>]. The pinned key is
   * the hub's 32-byte Ed25519 pubkey. */
  for (int i = 0; i < state->hub_count; i++) {
    if (state->hubs[i].ed_pub_set) {
      char *pb = base64_encode(state->hubs[i].ed_pub, 32);
      if (pb) {
        CFG_WRITE("h|%s|%s\n", state->hubs[i].addr, pb);
        free(pb);
      } else {
        CFG_WRITE("h|%s\n", state->hubs[i].addr);
      }
    } else {
      CFG_WRITE("h|%s\n", state->hubs[i].addr);
    }
  }

  if (state->hub_key[0] != '\0')
    CFG_WRITE("k|%s\n", state->hub_key);

  if (state->bot_uuid[0] != '\0')
    CFG_WRITE("i|%s\n", state->bot_uuid);

  /* Written with a timestamp even when empty, so a clear survives restart. */
  if (state->opt_flags[0] != '\0' || state->opt_flags_ts > 0)
    CFG_WRITE("O|%s|%lld\n", state->opt_flags, (long long)state->opt_flags_ts);

  if (state->admin_delta_pending)
    CFG_WRITE("D|1\n");

#undef CFG_WRITE

  if (overflow) {
    fprintf(stderr, "[CFG] Config exceeds %d bytes; NOT written (old config "
                    "kept).\n", cap);
    secure_wipe(plaintext_overrides, (size_t)cap);
    free(plaintext_overrides);
    return;
  }

  if (offset == 0) {
    free(plaintext_overrides);
    remove(CONFIG_FILE);
    return;
  }

  unsigned char salt[SALT_SIZE];
  unsigned char key[32];
  unsigned char iv[GCM_IV_LEN];
  bool key_ok;
  if (g_cfg_key.set) {
    memcpy(salt, g_cfg_key.salt, sizeof(salt));
    memcpy(key, g_cfg_key.key, sizeof(key));
    key_ok = true;
  } else {
    key_ok = RAND_bytes(salt, sizeof(salt)) == 1 &&
             crypto_derive_config_key(password, salt, PBKDF2_ITERATIONS, key);
    if (key_ok) cfg_key_keep(salt, key);
  }
  if (!key_ok || RAND_bytes(iv, sizeof(iv)) != 1) {
    fprintf(stderr, "[CFG] RNG/KDF failure; aborting config write.\n");
    secure_wipe(key, sizeof(key));
    secure_wipe(plaintext_overrides, (size_t)cap);
    free(plaintext_overrides);
    return;
  }

  unsigned char tag[GCM_TAG_LEN];
  int plaintext_len = offset;
  unsigned char *ciphertext = malloc((size_t)plaintext_len);
  if (!ciphertext) {
    secure_wipe(key, sizeof(key));
    secure_wipe(plaintext_overrides, (size_t)cap);
    handle_fatal_error("malloc failed for ciphertext");
  }
  int len = 0, ciphertext_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  bool enc_ok = ctx &&
      EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 1 &&
      EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len,
                        (unsigned char *)plaintext_overrides, plaintext_len) == 1 &&
      EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) == 1;
  if (ctx) EVP_CIPHER_CTX_free(ctx);
  secure_wipe(key, sizeof(key));
  secure_wipe(plaintext_overrides, (size_t)cap);
  free(plaintext_overrides);
  if (!enc_ok) {
    free(ciphertext);
    return;
  }
  ciphertext_len += len;

  char temp_file[256];
  snprintf(temp_file, sizeof(temp_file), "%s.tmp", CONFIG_FILE);

  int tmp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  FILE *out_file = (tmp_fd >= 0) ? fdopen(tmp_fd, "wb") : NULL;
  if (!out_file) {
    if (tmp_fd >= 0) close(tmp_fd);
    fprintf(stderr, "[CFG] Failed to open %s for writing: %s\n",
            temp_file, strerror(errno));
    free(ciphertext);
    return;
  }

  bool write_success =
      fwrite(salt,       1, sizeof(salt),       out_file) == sizeof(salt)       &&
      fwrite(iv,         1, sizeof(iv),         out_file) == sizeof(iv)         &&
      fwrite(tag,        1, sizeof(tag),         out_file) == sizeof(tag)        &&
      fwrite(ciphertext, 1, (size_t)ciphertext_len, out_file) == (size_t)ciphertext_len &&
      fflush(out_file) == 0 &&
      fsync(fileno(out_file)) == 0;

  fclose(out_file);
  free(ciphertext);

  if (!write_success) {
    fprintf(stderr, "[CFG] Failed to write config, keeping old config intact\n");
    remove(temp_file);
    return;
  }

  if (rename(temp_file, CONFIG_FILE) != 0) {
    fprintf(stderr, "[CFG] Failed to rename %s to %s: %s\n",
            temp_file, CONFIG_FILE, strerror(errno));
    remove(temp_file);
  }
}

void config_write(bot_state_t *state, const char *password) {
  config_write_file(state, password);
  if (state->hub_count > 0 && state->hub_authenticated)
    hub_client_push_config(state);
}

/* Save config to disk only — does NOT push to hub.
 * Use this when saving data received FROM the hub so we don't echo it back. */
void config_write_local(const bot_state_t *state, const char *password) {
  config_write_file(state, password);
}
