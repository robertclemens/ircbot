#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "bot.h"

void handle_crypto_errors_silent() { ERR_clear_error(); }

bool config_load(bot_state_t *state, const char *password,
                 const char *filename) {
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
  EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                 (unsigned char *)password, strlen(password), 1, key, NULL);

  unsigned char *plaintext = malloc(ciphertext_len + 1);
  if (!plaintext)
    handle_fatal_error("malloc failed for plaintext");
  int len;
  int plaintext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

  if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) > 0) {
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    // NEW: Pipe-delimited parser
    char *saveptr1;
    char *line = strtok_r((char *)plaintext, "\n", &saveptr1);

    while (line) {

      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\r')
        line[len - 1] = '\0';

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
        strncpy(state->target_nick, data, MAX_NICK - 1);
        state->target_nick[MAX_NICK - 1] = '\0';
        break;

      case 's': // Server (bot-specific)
        if (state->server_count < MAX_SERVERS) {
          state->server_list[state->server_count++] = strdup(data);
        }
        break;

      case 'c': // Channel (global, with timestamp)
      {
        char chan[MAX_CHAN], key[MAX_KEY], op[16];
        time_t ts = 0;

        // Parse: channel|key|add/del|timestamp
        int parsed =
            sscanf(data, "%64[^|]|%30[^|]|%15[^|]|%ld", chan, key, op, &ts);

        // Fallback for empty key: channel||add/del|timestamp
        if (parsed < 3) {
          parsed = sscanf(data, "%64[^|]||%15[^|]|%ld", chan, op, &ts);
          key[0] = '\0';
        }

        if (parsed >= 2) { // Need at least chan, op (key can be empty)
          // If fallback matched 3 items (chan, op, ts) or first matched 4
          // (chan,key,op,ts) Actually fallback matches 3 items. First matches 4
          // items. Adjust logic:

          chan_t *c = channel_add(state, chan);
          if (c) {
            if (strlen(key) > 0) {
              strncpy(c->key, key, MAX_KEY - 1);
              c->key[MAX_KEY - 1] = '\0';
            }
            c->is_managed = (strcmp(op, "del") != 0);
            c->timestamp = (ts > 0) ? ts : time(NULL);

            if (strlen(key) > 0)
              state->chan_count++;

            // Don't join deleted channels
            if (!c->is_managed) {
              c->status = C_OUT;
            }
          }
        }
      } break;

      case 'm': // Admin mask (global, with timestamp)
      {
        char mask[MAX_MASK_LEN], op[16];
        time_t ts = 0;

        // Parse: mask|add/del|timestamp
        int parsed = sscanf(data, "%127[^|]|%15[^|]|%ld", mask, op, &ts);

        if (parsed >= 2 && state->mask_count < MAX_MASKS) {
          size_t mask_len = strlen(mask);
          size_t copy_len =
              (mask_len < MAX_MASK_LEN) ? mask_len : MAX_MASK_LEN - 1;
          memcpy(state->auth_masks[state->mask_count].mask, mask, copy_len);
          state->auth_masks[state->mask_count].mask[copy_len] = '\0';
          state->auth_masks[state->mask_count].is_managed =
              (strcmp(op, "del") != 0);
          state->auth_masks[state->mask_count].timestamp =
              (parsed == 3) ? ts : time(NULL);
          state->mask_count++;
        }
      } break;

      case 'o': // Oper mask (global, with timestamp)
      {
        char mask[MAX_MASK_LEN], pass[MAX_PASS], op[16];
        time_t ts = 0;

        // Parse: mask|password|add/del|timestamp
        int parsed =
            sscanf(data, "%127[^|]|%127[^|]|%15[^|]|%ld", mask, pass, op, &ts);

        if (parsed >= 3 && strlen(pass) > 0 &&
            state->op_mask_count < MAX_OP_MASKS) {

          size_t mask_len = strlen(mask);
          size_t copy_len =
              (mask_len < MAX_MASK_LEN) ? mask_len : MAX_MASK_LEN - 1;
          memcpy(state->op_masks[state->op_mask_count].mask, mask, copy_len);
          state->op_masks[state->op_mask_count].mask[copy_len] = '\0';

          size_t pass_len = strlen(pass);
          size_t copy_len_pass =
              (pass_len < MAX_PASS) ? pass_len : MAX_PASS - 1;
          memcpy(state->op_masks[state->op_mask_count].password, pass,
                 copy_len_pass);
          state->op_masks[state->op_mask_count].password[copy_len_pass] = '\0';

          state->op_masks[state->op_mask_count].is_managed =
              (strcmp(op, "del") != 0);
          state->op_masks[state->op_mask_count].timestamp =
              (parsed == 4) ? ts : time(NULL);

          state->op_mask_count++;
        }
      } break;

      case 'a': // Admin password (global, no operation field)
      {
        // Format: a|password|timestamp (optional timestamp for legacy compat)
        char pass[MAX_PASS];
        time_t ts = 0;
        if (sscanf(data, "%127[^|]|%ld", pass, &ts) >= 1) {
          strncpy(state->bot_pass, pass, MAX_PASS - 1);
          state->bot_pass[MAX_PASS - 1] = '\0';
          state->bot_pass_ts = (ts > 0) ? ts : time(NULL);
        } else {
          // Legacy fallback
          strncpy(state->bot_pass, data, MAX_PASS - 1);
          state->bot_pass[MAX_PASS - 1] = '\0';
          state->bot_pass_ts = time(NULL);
        }
      } break;

      case 'p': // Bot password (global, no operation field)
      {
        char pass[MAX_PASS];
        time_t ts = 0;
        if (sscanf(data, "%127[^|]|%ld", pass, &ts) >= 1) {
          strncpy(state->bot_comm_pass, pass, MAX_PASS - 1);
          state->bot_comm_pass[MAX_PASS - 1] = '\0';
          state->bot_comm_pass_ts = (ts > 0) ? ts : time(NULL);
        } else {
          strncpy(state->bot_comm_pass, data, MAX_PASS - 1);
          state->bot_comm_pass[MAX_PASS - 1] = '\0';
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
        strncpy(state->user, data, sizeof(state->user) - 1);
        state->user[sizeof(state->user) - 1] = '\0';
        break;

      case 'g': // Gecos (bot-specific)
        strncpy(state->gecos, data, sizeof(state->gecos) - 1);
        state->gecos[sizeof(state->gecos) - 1] = '\0';
        break;

      case 'v': // Vhost (bot-specific)
        strncpy(state->vhost, data, sizeof(state->vhost) - 1);
        state->vhost[sizeof(state->vhost) - 1] = '\0';
        break;

      case 'h': // Hub list (bot-specific)
        if (state->hub_count < MAX_SERVERS) {
          state->hub_list[state->hub_count++] = strdup(data);
        }
        break;

      case 'k': // Hub public key (bot-specific)
        strncpy(state->hub_key, data, sizeof(state->hub_key) - 1);
        state->hub_key[sizeof(state->hub_key) - 1] = '\0';
        break;

      case 'i': // Bot UUID (bot-specific)
        strncpy(state->bot_uuid, data, sizeof(state->bot_uuid) - 1);
        state->bot_uuid[sizeof(state->bot_uuid) - 1] = '\0';
        break;
      }

      line = strtok_r(NULL, "\n", &saveptr1);
    }
  } else {
    log_message(
        L_INFO, state,
        "[CFG] GCM decryption failed. Incorrect password or corrupt file.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);
    return false;
  }

  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);
  free(plaintext);
  // Validation changed
  if (state->target_nick[0] == '\0' || state->server_count == 0 ||
      state->user[0] == '\0') {
    log_message(L_INFO, state,
                "[CFG] Config file is missing required fields (Nick, Server, "
                "or Ident).\n");
    return false;
  }
  // Validation
  // if (state->target_nick[0] == '\0' || state->user[0] == '\0' ||
  // state->gecos[0] == '\0' ||
  //       state->bot_pass[0] == '\0' || state->mask_count == 0 ||
  //        state->server_count == 0 || state->chan_count == 0) {
  //        log_message(L_INFO, state, "[CFG] Config file is missing required
  //        fields.\n"); return false;
  //    }
  return true;
}

void config_write(const bot_state_t *state, const char *password) {
  if (strlen(password) > MAX_PASS) {
    return;
  }

  char plaintext_overrides[MAX_BUFFER * 4] = "";
  int offset = 0;
  int remaining = sizeof(plaintext_overrides);
  int written;

  // Nickname (bot-specific, no timestamp)
  written = snprintf(plaintext_overrides + offset, remaining, "n|%s\n",
                     state->target_nick);
  if (written > 0 && written < remaining) {
    offset += written;
    remaining -= written;
  }

  // Servers (bot-specific, no timestamp)
  for (int i = 0; i < state->server_count; i++) {
    if (remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "s|%s\n",
                         state->server_list[i]);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Channels (global, with timestamp)
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (remaining > 1) {
      const char *key = (c->key[0] != '\0') ? c->key : "";
      const char *operation = c->is_managed ? "add" : "del";

      written =
          snprintf(plaintext_overrides + offset, remaining, "c|%s|%s|%s|%ld\n",
                   c->name, key, operation, (long)c->timestamp);

      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Admin masks (global, with timestamp)
  for (int i = 0; i < state->mask_count; i++) {
    if (remaining > 1) {
      const char *operation = state->auth_masks[i].is_managed ? "add" : "del";

      written = snprintf(plaintext_overrides + offset, remaining,
                         "m|%s|%s|%ld\n", state->auth_masks[i].mask, operation,
                         (long)state->auth_masks[i].timestamp);

      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Oper masks (global, with timestamp)
  for (int i = 0; i < state->op_mask_count; i++) {
    if (remaining > 1) {
      const char *operation = state->op_masks[i].is_managed ? "add" : "del";

      written =
          snprintf(plaintext_overrides + offset, remaining, "o|%s|%s|%s|%ld\n",
                   state->op_masks[i].mask, state->op_masks[i].password,
                   operation, (long)state->op_masks[i].timestamp);

      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Admin password (global, no timestamp, no operation)
  written = snprintf(plaintext_overrides + offset, remaining, "a|%s|%ld\n",
                     state->bot_pass, (long)state->bot_pass_ts);
  if (written > 0 && written < remaining) {
    offset += written;
    remaining -= written;
  }

  // Bot password (global, no timestamp, no operation)
  if (state->bot_comm_pass[0] != '\0') {
    written = snprintf(plaintext_overrides + offset, remaining, "p|%s|%ld\n",
                       state->bot_comm_pass, (long)state->bot_comm_pass_ts);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }

  // Bot lines (hub-generated, no timestamp)
  for (int i = 0; i < state->trusted_bot_count; i++) {
    if (remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "b|%s\n",
                         state->trusted_bots[i]);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Log level (optional, bot-specific)
  if (state->log_type != DEFAULT_LOG_LEVEL) {
    written = snprintf(plaintext_overrides + offset, remaining, "l|%d\n",
                       state->log_type);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }

  // User (ident) - bot-specific
  written =
      snprintf(plaintext_overrides + offset, remaining, "u|%s\n", state->user);
  if (written > 0 && written < remaining) {
    offset += written;
    remaining -= written;
  }

  // Gecos - bot-specific
  written =
      snprintf(plaintext_overrides + offset, remaining, "g|%s\n", state->gecos);
  if (written > 0 && written < remaining) {
    offset += written;
    remaining -= written;
  }

  // Vhost (optional) - bot-specific
  if (state->vhost[0] != '\0') {
    written = snprintf(plaintext_overrides + offset, remaining, "v|%s\n",
                       state->vhost);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }

  // Hub list (bot-specific)
  for (int i = 0; i < state->hub_count; i++) {
    if (remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "h|%s\n",
                         state->hub_list[i]);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  // Hub public key (bot-specific)
  if (state->hub_key[0] != '\0') {
    written = snprintf(plaintext_overrides + offset, remaining, "k|%s\n",
                       state->hub_key);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }

  // Bot UUID (bot-specific)
  if (state->bot_uuid[0] != '\0') {
    written = snprintf(plaintext_overrides + offset, remaining, "i|%s\n",
                       state->bot_uuid);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }

  if (strlen(plaintext_overrides) == 0) {
    remove(CONFIG_FILE);
    return;
  }

  unsigned char salt[SALT_SIZE];
  RAND_bytes(salt, sizeof(salt));

  unsigned char key[32];
  EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), salt,
                 (unsigned char *)password, strlen(password), 1, key, NULL);

  unsigned char iv[GCM_IV_LEN];
  RAND_bytes(iv, sizeof(iv));

  unsigned char tag[GCM_TAG_LEN];
  int plaintext_len = strlen(plaintext_overrides);
  unsigned char *ciphertext = malloc(plaintext_len);
  if (!ciphertext)
    handle_fatal_error("malloc failed for ciphertext");
  int len, ciphertext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len,
                    (unsigned char *)plaintext_overrides, plaintext_len);
  EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
  ciphertext_len += len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
  EVP_CIPHER_CTX_free(ctx);

  FILE *out_file = fopen(CONFIG_FILE, "wb");
  if (!out_file) {
    fprintf(stderr, "[CFG] Failed to open %s for writing: %s\n", CONFIG_FILE,
            strerror(errno));
    free(ciphertext);
    return;
  }

  fwrite(salt, 1, sizeof(salt), out_file);
  fwrite(iv, 1, sizeof(iv), out_file);
  fwrite(tag, 1, sizeof(tag), out_file);
  fwrite(ciphertext, 1, ciphertext_len, out_file);

  fclose(out_file);
  free(ciphertext);
  chmod(CONFIG_FILE, S_IRUSR | S_IWUSR);
  if (state->hub_count > 0 && state->hub_authenticated) {
    hub_client_push_config((bot_state_t *)state);
  }
}
