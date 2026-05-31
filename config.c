#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bot.h"

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

  unsigned char *ciphertext = malloc(ciphertext_len);
  if (!ciphertext)
    handle_fatal_error("malloc failed for ciphertext");

  if (fread(ciphertext, 1, ciphertext_len, in_file) != (size_t)ciphertext_len) {
    log_message(
        L_INFO, state,
        "[CFG] Error: Could not read the full contents of the config file.\n");
    fclose(in_file);
    free(ciphertext);
    return false;
  }
  fclose(in_file);

  unsigned char key[32];
  if (!crypto_derive_config_key(password, salt, key)) {
    free(ciphertext);
    return false;
  }

  unsigned char *plaintext = malloc(ciphertext_len + 1);
  if (!plaintext)
    handle_fatal_error("malloc failed for plaintext");
  int len;
  int plaintext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    secure_wipe(key, sizeof(key));
    free(ciphertext);
    free(plaintext);
    return false;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
      EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext,
                        ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    secure_wipe(plaintext, (size_t)ciphertext_len);
    free(ciphertext);
    free(plaintext);
    return false;
  }
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

  int final_rc = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);
  EVP_CIPHER_CTX_free(ctx);
  bool migrated_from_legacy = false;
  if (final_rc <= 0) {
    /* PBKDF2 key failed GCM tag check — try legacy EVP_BytesToKey for
     * one-time migration of configs written before the PBKDF2 upgrade.
     * On success the config is immediately re-written with PBKDF2. */
    secure_wipe(plaintext, (size_t)ciphertext_len);
    unsigned char legacy_key[32];
    if (EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                       (unsigned char *)password, (int)strlen(password),
                       1, legacy_key, NULL) > 0) {
      EVP_CIPHER_CTX *lctx = EVP_CIPHER_CTX_new();
      if (lctx) {
        int lpl = 0, ll = 0;
        if (EVP_DecryptInit_ex(lctx, EVP_aes_256_gcm(), NULL, legacy_key, iv) == 1 &&
            EVP_DecryptUpdate(lctx, plaintext, &lpl, ciphertext, ciphertext_len) == 1) {
          EVP_CIPHER_CTX_ctrl(lctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);
          int lrc = EVP_DecryptFinal_ex(lctx, plaintext + lpl, &ll);
          if (lrc > 0) {
            plaintext_len = lpl + ll;
            migrated_from_legacy = true;
            final_rc = 1;
          } else {
            secure_wipe(plaintext, (size_t)ciphertext_len);
          }
        }
        EVP_CIPHER_CTX_free(lctx);
      }
      secure_wipe(legacy_key, sizeof(legacy_key));
    }
    if (final_rc <= 0) {
      log_message(L_INFO, state, "[CFG] Decryption failed (wrong password?).\n");
      secure_wipe(key, sizeof(key));
      free(ciphertext);
      free(plaintext);
      return false;
    }
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
        time_t ts = 0;

        // Parse: channel|key|add/del|timestamp
        int parsed =
            sscanf(data, "%64[^|]|%30[^|]|%15[^|]|%ld", chan, chan_key, op, &ts);

        // Fallback for empty key: channel||add/del|timestamp
        if (parsed < 3) {
          parsed = sscanf(data, "%64[^|]||%15[^|]|%ld", chan, op, &ts);
          chan_key[0] = '\0';
        }

        if (parsed >= 2) { // Need at least chan, op (key can be empty)
          // If fallback matched 3 items (chan, op, ts) or first matched 4
          // (chan,key,op,ts) Actually fallback matches 3 items. First matches 4
          // items. Adjust logic:

          chan_t *c = channel_add(state, chan);
          if (c) {
            if (strlen(chan_key) > 0) {
              snprintf(c->key, MAX_KEY, "%s", chan_key);
            }
            c->is_managed = (strcmp(op, "del") != 0);
            c->timestamp = (ts > 0) ? ts : time(NULL);

            if (strlen(chan_key) > 0)
              state->chan_count++;

            // Don't join deleted channels
            if (!c->is_managed) {
              c->status = C_OUT;
            }
          }
        }
      } break;

      case 'm': // Usermask record (new: uuid|mask|add/del|last_used|ts  old: mask|add/del|ts)
      {
        char first[40] = {0};
        char *p = strchr(data, '|');
        if (p) {
          size_t fl = (size_t)(p - data);
          if (fl < sizeof(first)) { memcpy(first, data, fl); first[fl] = 0; }
        }
        bool is_new = (strlen(first) == 36 && first[8]=='-' &&
                       first[13]=='-' && first[18]=='-' && first[23]=='-');

        if (is_new && state->mask_record_count < MAX_USER_MASKS) {
          mask_record_t *m = &state->mask_records[state->mask_record_count];
          memset(m, 0, sizeof(*m));
          char *p1 = strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
          char *p3 = p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
          if (p1 && p2 && p3 && p4) {
            snprintf(m->uuid,  sizeof(m->uuid),  "%.*s",(int)(p1-data),data);
            snprintf(m->mask,  sizeof(m->mask),  "%.*s",(int)(p2-p1-1),p1+1);
            m->is_active = (strncmp(p2+1,"add",3)==0);
            m->last_used = (time_t)atol(p3+1);
            m->timestamp = (time_t)atol(p4+1);
            state->mask_record_count++;
          }
        } else if (!is_new && state->mask_record_count < MAX_USER_MASKS) {
          /* Old format: mask|add/del|timestamp — tag with MIGRATE sentinel */
          mask_record_t *m = &state->mask_records[state->mask_record_count];
          memset(m, 0, sizeof(*m));
          snprintf(m->uuid, sizeof(m->uuid), "MIGRATE");
          char mask[MAX_MASK_LEN], op[16]; time_t ts = 0;
          if (sscanf(data, "%255[^|]|%15[^|]|%ld", mask, op, &ts) >= 2) {
            snprintf(m->mask, sizeof(m->mask), "%s", mask);
            m->is_active = (strcmp(op,"del") != 0);
            m->timestamp = (ts > 0) ? ts : time(NULL);
            state->mask_record_count++;
          }
        }
      } break;

      case 'o': // Oper record (new: uuid|name|pass|add/del|last_seen|ts[|pubkey_b64]; old: mask|pass|add/del|ts)
      {
        char first[40] = {0};
        char *p = strchr(data, '|');
        if (p) {
          size_t fl = (size_t)(p - data);
          if (fl < sizeof(first)) { memcpy(first, data, fl); first[fl] = 0; }
        }
        bool is_new = (strlen(first) == 36 && first[8]=='-' &&
                       first[13]=='-' && first[18]=='-' && first[23]=='-');

        if (is_new && state->user_record_count < MAX_USER_RECORDS) {
          user_record_t *u = &state->user_records[state->user_record_count];
          memset(u, 0, sizeof(*u));
          char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
          char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
          char *p5=p4?strchr(p4+1,'|'):NULL, *p6=p5?strchr(p5+1,'|'):NULL;
          if (p1&&p2&&p3&&p4&&p5) {
            snprintf(u->uuid,     sizeof(u->uuid),     "%.*s",(int)(p1-data),data);
            snprintf(u->name,     sizeof(u->name),     "%.*s",(int)(p2-p1-1),p1+1);
            snprintf(u->password, sizeof(u->password), "%.*s",(int)(p3-p2-1),p2+1);
            u->type      = 'o';
            u->is_active = (strncmp(p3+1,"add",3)==0);
            u->last_seen = (time_t)atol(p4+1);
            if (p6) {
              char ts_buf[32];
              snprintf(ts_buf, sizeof(ts_buf), "%.*s", (int)(p6-p5-1), p5+1);
              u->timestamp = (time_t)atol(ts_buf);
              snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", p6+1);
              u->has_pubkey = (strlen(u->pubkey_b64) == COMBINED_KEY_B64);
            } else {
              u->timestamp = (time_t)atol(p5+1);
            }
            state->user_record_count++;
          }
        } else if (!is_new && state->user_record_count < MAX_USER_RECORDS) {
          /* Old format o|mask|password|add/del|timestamp — tag with MIGRATE sentinel */
          user_record_t *u = &state->user_records[state->user_record_count];
          memset(u, 0, sizeof(*u));
          snprintf(u->uuid, sizeof(u->uuid), "MIGRATE_O");
          u->type = 'o';
          char mask[MAX_MASK_LEN], pass[MAX_PASS], op[16]; time_t ts = 0;
          if (sscanf(data,"%255[^|]|%127[^|]|%15[^|]|%ld",mask,pass,op,&ts)>=3) {
            /* Store mask in name temporarily; real name derived at migration */
            snprintf(u->name,     sizeof(u->name),     "%.63s", mask);
            snprintf(u->password, sizeof(u->password), "%s", pass);
            u->is_active = (strcmp(op,"del")!=0);
            u->timestamp = (ts > 0) ? ts : time(NULL);
            state->user_record_count++;
          }
        }
      } break;

      case 'a': // Admin record (new: uuid|name|pass|add/del|last_seen|ts[|pubkey_b64]; old: pass|ts)
      {
        char first[40] = {0};
        char *p = strchr(data, '|');
        if (p) {
          size_t fl = (size_t)(p - data);
          if (fl < sizeof(first)) { memcpy(first, data, fl); first[fl] = 0; }
        }
        bool is_new = (strlen(first) == 36 && first[8]=='-' &&
                       first[13]=='-' && first[18]=='-' && first[23]=='-');

        if (is_new && state->user_record_count < MAX_USER_RECORDS) {
          user_record_t *u = &state->user_records[state->user_record_count];
          memset(u, 0, sizeof(*u));
          char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
          char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
          char *p5=p4?strchr(p4+1,'|'):NULL, *p6=p5?strchr(p5+1,'|'):NULL;
          if (p1&&p2&&p3&&p4&&p5) {
            snprintf(u->uuid,     sizeof(u->uuid),     "%.*s",(int)(p1-data),data);
            snprintf(u->name,     sizeof(u->name),     "%.*s",(int)(p2-p1-1),p1+1);
            snprintf(u->password, sizeof(u->password), "%.*s",(int)(p3-p2-1),p2+1);
            u->type      = 'a';
            u->is_active = (strncmp(p3+1,"add",3)==0);
            u->last_seen = (time_t)atol(p4+1);
            if (p6) {
              char ts_buf[32];
              snprintf(ts_buf, sizeof(ts_buf), "%.*s", (int)(p6-p5-1), p5+1);
              u->timestamp = (time_t)atol(ts_buf);
              snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", p6+1);
              u->has_pubkey = (strlen(u->pubkey_b64) == COMBINED_KEY_B64);
            } else {
              u->timestamp = (time_t)atol(p5+1);
            }
            state->user_record_count++;
          }
        } else if (!is_new && state->user_record_count < MAX_USER_RECORDS) {
          /* Old format a|password|timestamp — MIGRATE sentinel */
          user_record_t *u = &state->user_records[state->user_record_count];
          memset(u, 0, sizeof(*u));
          snprintf(u->uuid, sizeof(u->uuid), "MIGRATE");
          u->type = 'a';
          char pass[MAX_PASS]; time_t ts = 0;
          if (sscanf(data, "%127[^|]|%ld", pass, &ts) >= 1) {
            snprintf(u->password, sizeof(u->password), "%s", pass);
            u->timestamp = (ts > 0) ? ts : time(NULL);
          } else {
            snprintf(u->password, sizeof(u->password), "%s", data);
            u->timestamp = time(NULL);
          }
          state->user_record_count++;
        }
      } break;

      case 'p': // Bot password (global, no operation field)
      {
        char pass[MAX_PASS];
        time_t ts = 0;
        if (sscanf(data, "%127[^|]|%ld", pass, &ts) >= 1) {
          snprintf(state->bot_comm_pass, MAX_PASS, "%s", pass);
          state->bot_comm_pass_ts = (ts > 0) ? ts : time(NULL);
        } else {
          snprintf(state->bot_comm_pass, MAX_PASS, "%s", data);
          state->bot_comm_pass_ts = time(NULL);
        }
      } break;

      case 'b': // Bot line (hub-generated, no timestamp)
        if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
          state->trusted_bots[state->trusted_bot_count++] = strdup(data);
        }
        break;

      case 'l': // Log level (bot-specific)
        state->log_type = (log_type_t)atoi(data);
        break;

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
                 * matching hub_public.b64). Lines with no pubkey are accepted
                 * for migration; the post-load pass below fills them from a
                 * legacy global 'j|' key if one was present. */
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
                      "Curve25519 key (legacy RSA?). Re-run 'ircbot -setup' "
                      "to regenerate the bot's identity.\n");
        }
        if (dec) { secure_wipe(dec, 64); free(dec); }
        break;
      }

      case 'j': { /* LEGACY single global hub Ed25519 PUBLIC key. Superseded by
                   * per-hub pinning on the 'h|' line. Still parsed so existing
                   * configs migrate: the post-load pass copies this into any
                   * hub entry that lacks its own pinned key, after which it is
                   * dropped (no 'j|' is written back out).
                   * 32 raw bytes, base64 = 44 chars. */
        int dec_len = 0;
        unsigned char *dec = base64_decode(data, &dec_len);
        if (dec && dec_len == 32) {
          memcpy(state->hub_remote_ed_pub, dec, 32);
          state->hub_remote_ed_pub_set = true;
        } else {
          log_message(L_INFO, state,
                      "[CFG] Legacy 'j|' hub pubkey is not 32 raw bytes — "
                      "ignored. Pin per-hub keys with '+hub <host:port> "
                      "<pubkey>'.\n");
        }
        if (dec) { secure_wipe(dec, (size_t)(dec_len > 0 ? dec_len : 0)); free(dec); }
        break;
      }

      case 'i': // Bot UUID (bot-specific)
        snprintf(state->bot_uuid, sizeof(state->bot_uuid), "%s", data);
        break;

      case 'O': /* Network options string: O|<letters>|<timestamp>
                 * (Stored under the 'O' line — single capital letter so it
                 * cannot collide with the existing 'o' oper record line.) */
      {
        char flags[MAX_OPT_FLAGS + 1] = {0};
        long ts = 0;
        if (sscanf(data, "%32[^|]|%ld", flags, &ts) >= 1) {
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

  secure_wipe(key, sizeof(key));
  secure_wipe(plaintext, (size_t)plaintext_len);
  free(ciphertext);
  free(plaintext);

  /* Migration: a legacy 'j|' global hub pubkey applies to every hub that did
   * not carry its own pinned key on the 'h|' line. Fill them in so the next
   * config write emits per-hub 'h|addr|pub' lines and drops the global 'j|'. */
  if (state->hub_remote_ed_pub_set) {
    for (int i = 0; i < state->hub_count; i++) {
      if (!state->hubs[i].ed_pub_set) {
        memcpy(state->hubs[i].ed_pub, state->hub_remote_ed_pub, 32);
        state->hubs[i].ed_pub_set = true;
      }
    }
  }

  /* Migration: convert old-format MIGRATE sentinel records to new typed records */
  bool needs_migration = false;
  for (int i = 0; i < state->user_record_count && !needs_migration; i++)
    if (strncmp(state->user_records[i].uuid, "MIGRATE", 7) == 0)
      needs_migration = true;
  for (int i = 0; i < state->mask_record_count && !needs_migration; i++)
    if (strcmp(state->mask_records[i].uuid, "MIGRATE") == 0)
      needs_migration = true;

  if (needs_migration) {
    time_t now = time(NULL);

    /* Generate a simple UUID-like value using random bytes */
    unsigned char rnd[16];
    RAND_bytes(rnd, sizeof(rnd));
    rnd[6] = (rnd[6] & 0x0f) | 0x40; /* version 4 */
    rnd[8] = (rnd[8] & 0x3f) | 0x80; /* variant */
    char admin_uuid[37];
    snprintf(admin_uuid, sizeof(admin_uuid),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
             rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);

    user_record_t new_users[MAX_USER_RECORDS];
    mask_record_t new_masks[MAX_USER_MASKS];
    int nu = 0, nm = 0;
    memset(new_users, 0, sizeof(new_users));
    memset(new_masks, 0, sizeof(new_masks));

    /* Build admin record from MIGRATE sentinel */
    for (int i = 0; i < state->user_record_count; i++) {
      user_record_t *u = &state->user_records[i];
      if (strcmp(u->uuid, "MIGRATE") == 0 && u->type == 'a' && nu < MAX_USER_RECORDS) {
        user_record_t *nu_rec = &new_users[nu++];
        snprintf(nu_rec->uuid,     sizeof(nu_rec->uuid),     "%s", admin_uuid);
        snprintf(nu_rec->name,     sizeof(nu_rec->name),     "admin");
        snprintf(nu_rec->password, sizeof(nu_rec->password), "%s", u->password);
        nu_rec->type      = 'a';
        nu_rec->is_active = true;
        nu_rec->last_seen = 0;
        nu_rec->timestamp = u->timestamp ? u->timestamp : now;
        break;
      }
    }

    /* Migrate old mask records under admin uuid */
    for (int i = 0; i < state->mask_record_count; i++) {
      if (strcmp(state->mask_records[i].uuid, "MIGRATE") != 0) continue;
      if (nm >= MAX_USER_MASKS) break;
      mask_record_t *mr = &new_masks[nm++];
      snprintf(mr->uuid, sizeof(mr->uuid), "%s", admin_uuid);
      snprintf(mr->mask, sizeof(mr->mask), "%s", state->mask_records[i].mask);
      mr->is_active = state->mask_records[i].is_active;
      mr->last_used = 0;
      mr->timestamp = state->mask_records[i].timestamp;
    }

    /* Migrate old oper records (MIGRATE_O sentinel), generating individual UUIDs */
    for (int i = 0; i < state->user_record_count; i++) {
      user_record_t *u = &state->user_records[i];
      if (strcmp(u->uuid, "MIGRATE_O") != 0 || nu >= MAX_USER_RECORDS) continue;
      unsigned char ornd[16];
      RAND_bytes(ornd, sizeof(ornd));
      ornd[6] = (ornd[6] & 0x0f) | 0x40;
      ornd[8] = (ornd[8] & 0x3f) | 0x80;
      char ouuid[37];
      snprintf(ouuid, sizeof(ouuid),
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               ornd[0],ornd[1],ornd[2],ornd[3],ornd[4],ornd[5],ornd[6],ornd[7],
               ornd[8],ornd[9],ornd[10],ornd[11],ornd[12],ornd[13],ornd[14],ornd[15]);
      /* Derive name from nick portion of old mask (everything before !) */
      char derived_name[64] = {0};
      char *bang = strchr(u->name, '!');
      if (bang) {
        size_t nlen = (size_t)(bang - u->name);
        if (nlen >= sizeof(derived_name)) nlen = sizeof(derived_name) - 1;
        memcpy(derived_name, u->name, nlen);
      } else {
        snprintf(derived_name, sizeof(derived_name), "oper%d", i);
      }
      /* Deduplicate name */
      bool collision = true;
      int suffix = 2;
      char try_name[64];
      snprintf(try_name, sizeof(try_name), "%s", derived_name);
      while (collision) {
        collision = false;
        for (int j = 0; j < nu; j++) {
          if (strcmp(new_users[j].name, try_name) == 0) {
            collision = true;
            snprintf(try_name, sizeof(try_name), "%s_%d", derived_name, suffix++);
            break;
          }
        }
      }
      user_record_t *nr = &new_users[nu++];
      snprintf(nr->uuid,     sizeof(nr->uuid),     "%s", ouuid);
      snprintf(nr->name,     sizeof(nr->name),     "%s", try_name);
      snprintf(nr->password, sizeof(nr->password), "%s", u->password);
      nr->type      = 'o';
      nr->is_active = u->is_active;
      nr->last_seen = 0;
      nr->timestamp = u->timestamp ? u->timestamp : now;
      /* Add the old mask as a mask record under this oper's uuid */
      if (nm < MAX_USER_MASKS) {
        mask_record_t *mr = &new_masks[nm++];
        snprintf(mr->uuid, sizeof(mr->uuid), "%s", ouuid);
        /* u->name holds the old mask string */
        snprintf(mr->mask, sizeof(mr->mask), "%s", u->name);
        mr->is_active = u->is_active;
        mr->last_used = 0;
        mr->timestamp = u->timestamp ? u->timestamp : now;
      }
    }

    /* Copy already-clean records */
    for (int i = 0; i < state->user_record_count; i++) {
      if (strncmp(state->user_records[i].uuid, "MIGRATE", 7) == 0) continue;
      if (nu >= MAX_USER_RECORDS) break;
      new_users[nu++] = state->user_records[i];
    }
    for (int i = 0; i < state->mask_record_count; i++) {
      if (strcmp(state->mask_records[i].uuid, "MIGRATE") == 0) continue;
      if (nm >= MAX_USER_MASKS) break;
      new_masks[nm++] = state->mask_records[i];
    }

    memcpy(state->user_records, new_users, sizeof(new_users));
    state->user_record_count = nu;
    memcpy(state->mask_records, new_masks, sizeof(new_masks));
    state->mask_record_count = nm;

    if (migrated_from_legacy)
      log_message(L_INFO, state,
                  "[CFG] Config re-encrypted with PBKDF2 (legacy migration).\n");
    /* Write migrated config immediately */
    config_write(state, password);
  } else if (migrated_from_legacy) {
    log_message(L_INFO, state,
                "[CFG] Config re-encrypted with PBKDF2 (legacy migration).\n");
    config_write(state, password);
  }

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
  if (strlen(password) >= MAX_PASS)
    return;

  char plaintext_overrides[MAX_BUFFER * 4] = "";
  int offset = 0;
  int remaining = sizeof(plaintext_overrides);
  int written;

#define CFG_WRITE(...)                                          \
  do {                                                          \
    if (remaining > 1) {                                        \
      written = snprintf(plaintext_overrides + offset,          \
                         remaining, __VA_ARGS__);               \
      if (written > 0 && written < remaining) {                 \
        offset += written; remaining -= written;                \
      }                                                         \
    }                                                           \
  } while (0)

  CFG_WRITE("n|%s\n", state->target_nick);

  for (int i = 0; i < state->server_count; i++)
    CFG_WRITE("s|%s\n", state->server_list[i]);

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    const char *key = (c->key[0] != '\0') ? c->key : "";
    CFG_WRITE("c|%s|%s|%s|%ld\n",
              c->name, key, c->is_managed ? "add" : "del", (long)c->timestamp);
  }

  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *u = &state->user_records[i];
    CFG_WRITE("%c|%s|%s|%s|%s|%ld|%ld|%s\n",
              u->type, u->uuid, u->name, u->password,
              u->is_active ? "add" : "del",
              (long)u->last_seen, (long)u->timestamp,
              u->has_pubkey ? u->pubkey_b64 : "");
  }

  for (int i = 0; i < state->mask_record_count; i++) {
    const mask_record_t *m = &state->mask_records[i];
    CFG_WRITE("m|%s|%s|%s|%ld|%ld\n",
              m->uuid, m->mask, m->is_active ? "add" : "del",
              (long)m->last_used, (long)m->timestamp);
  }

  if (state->bot_comm_pass[0] != '\0')
    CFG_WRITE("p|%s|%ld\n", state->bot_comm_pass, (long)state->bot_comm_pass_ts);

  for (int i = 0; i < state->trusted_bot_count; i++)
    CFG_WRITE("b|%s\n", state->trusted_bots[i]);

  if (state->log_type != DEFAULT_LOG_LEVEL)
    CFG_WRITE("l|%d\n", state->log_type);

  CFG_WRITE("u|%s\n", state->user);
  CFG_WRITE("g|%s\n", state->gecos);

  if (state->vhost[0] != '\0')
    CFG_WRITE("v|%s\n", state->vhost);

  /* Per-hub entries: h|<host:port>[|<pinned-pubkey-b64>]. The pinned key is
   * the hub's 32-byte Ed25519 pubkey; the legacy global 'j|' line is no longer
   * written (its value was migrated into the per-hub keys at load time). */
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

  if (state->opt_flags[0] != '\0')
    CFG_WRITE("O|%s|%ld\n", state->opt_flags, (long)state->opt_flags_ts);

#undef CFG_WRITE

  if (strlen(plaintext_overrides) == 0) {
    remove(CONFIG_FILE);
    return;
  }

  unsigned char salt[SALT_SIZE];
  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    fprintf(stderr, "[CFG] RAND_bytes failed for salt; aborting write.\n");
    return;
  }

  unsigned char key[32];
  if (!crypto_derive_config_key(password, salt, key)) {
    fprintf(stderr, "[CFG] PBKDF2 key derivation failed; aborting write.\n");
    return;
  }

  unsigned char iv[GCM_IV_LEN];
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    fprintf(stderr, "[CFG] RAND_bytes failed for IV; aborting write.\n");
    secure_wipe(key, sizeof(key));
    return;
  }

  unsigned char tag[GCM_TAG_LEN];
  int plaintext_len = strlen(plaintext_overrides);
  unsigned char *ciphertext = malloc(plaintext_len);
  if (!ciphertext) {
    secure_wipe(key, sizeof(key));
    handle_fatal_error("malloc failed for ciphertext");
  }
  int len, ciphertext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { secure_wipe(key, sizeof(key)); free(ciphertext); return; }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
      EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len,
                        (unsigned char *)plaintext_overrides, plaintext_len) != 1 ||
      EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    free(ciphertext);
    return;
  }
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  secure_wipe(key, sizeof(key));

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
      fwrite(ciphertext, 1, ciphertext_len,      out_file) == (size_t)ciphertext_len &&
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

void config_write(const bot_state_t *state, const char *password) {
  config_write_file(state, password);
  if (state->hub_count > 0 && state->hub_authenticated)
    hub_client_push_config((bot_state_t *)state);
}

/* Save config to disk only — does NOT push to hub.
 * Use this when saving data received FROM the hub so we don't echo it back. */
void config_write_local(const bot_state_t *state, const char *password) {
  config_write_file(state, password);
}
