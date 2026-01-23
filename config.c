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
void config_notify_hub_if_changed(bot_state_t *state);


void config_notify_hub_if_changed(bot_state_t *state) {
    static time_t last_hub_sync = 0;
    static bool config_dirty = false;
    time_t now = time(NULL);
    
    config_dirty = true;  // Mark that config changed
    
    if (now - last_hub_sync < 10) return;  // Still debouncing
    
    if (config_dirty && state->hub_authenticated) {
        log_message(L_INFO, state, "[HUB] Config changed - syncing to hub\n");
        hub_client_promote_local_config(state);
        last_hub_sync = now;
        config_dirty = false;
    }
}

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
    log_message(L_INFO, state, "[CFG] Error: Config file is empty or too large (Max 1MB).\n");
    fclose(in_file);
    return false;
  }

  unsigned char *ciphertext = malloc(ciphertext_len);
  if (!ciphertext) handle_fatal_error("malloc failed for ciphertext");

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
  if (!plaintext) handle_fatal_error("malloc failed for plaintext");
  int len;
  int plaintext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

  if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) > 0) {
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    char *saveptr1;
    char *line = strtok_r((char *)plaintext, "\n", &saveptr1);

    while (line) {
      if (strlen(line) < 2 || line[0] == '#') {
        line = strtok_r(NULL, "\n", &saveptr1);
        continue;
      }

      char *value = strchr(line, ':');
      if (!value) {
        line = strtok_r(NULL, "\n", &saveptr1);
        continue;
      }
      *value++ = '\0';
      
      // Identity
      if (strcmp(line, "uuid") == 0) {
          strncpy(state->bot_uuid, value, sizeof(state->bot_uuid) - 1);
      }
      else if (strcmp(line, "hk") == 0) {
          strncpy(state->hub_key, value, sizeof(state->hub_key) - 1);
      }
      else if (strcmp(line, "hub") == 0) {
          if (state->hub_count < MAX_SERVERS) {
              state->hub_list[state->hub_count++] = strdup(value);
          }
      }
      // Managed Channel (hc) or Local (c)
      else if (strcmp(line, "c") == 0 || strcmp(line, "hc") == 0) {
          bool is_managed = (line[0] == 'h');
          char *saveptr2;
          char *chan_info = value;
          char *ts_str = NULL;
          if (is_managed) {
              ts_str = strchr(value, '|');
              if (ts_str) *ts_str++ = '\0';
          }

          char *chan_name = strtok_r(chan_info, " ", &saveptr2);
          char *chan_key = strtok_r(NULL, " ", &saveptr2);
          
          if (chan_name) {
            chan_t *c = channel_add(state, chan_name);
            if (c) {
                if (chan_key) strncpy(c->key, chan_key, MAX_KEY - 1);
                c->is_managed = is_managed;
                if (ts_str) c->timestamp = atol(ts_str);
            }
          }
      }
      // Managed Admin (hm) or Local (m)
      else if (strcmp(line, "m") == 0 || strcmp(line, "hm") == 0) {
          if (state->mask_count < MAX_MASKS) {
              bool is_managed = (line[0] == 'h');
              char *mask_info = value;
              char *ts_str = NULL;
              if (is_managed) {
                  ts_str = strchr(value, '|');
                  if (ts_str) *ts_str++ = '\0';
              }
              
              admin_entry_t *entry = &state->auth_masks[state->mask_count++];
              strncpy(entry->mask, mask_info, MAX_MASK_LEN - 1);
              entry->is_managed = is_managed;
              if (ts_str) entry->timestamp = atol(ts_str);
          }
      }
      // Managed Oper (ho) or Local (o)
      else if (strcmp(line, "o") == 0 || strcmp(line, "ho") == 0) {
          if (state->op_mask_count < MAX_OP_MASKS) {
              bool is_managed = (line[0] == 'h');
              char *op_info = value;
              char *ts_str = NULL;
              if (is_managed) {
                  ts_str = strchr(value, '|');
                  if (ts_str) *ts_str++ = '\0';
              }

              char *saveptr_o;
              char *mask = strtok_r(op_info, ":", &saveptr_o);
              char *pass = strtok_r(NULL, ":", &saveptr_o);
              
              if (mask && pass) {
                  op_entry_t *entry = &state->op_masks[state->op_mask_count++];
                  strncpy(entry->mask, mask, MAX_MASK_LEN - 1);
                  strncpy(entry->password, pass, MAX_PASS - 1);
                  entry->is_managed = is_managed;
                  if (ts_str) entry->timestamp = atol(ts_str);
              }
          }
      }
      else if (strcmp(line, "n") == 0) strncpy(state->target_nick, value, MAX_NICK - 1);
      else if (strcmp(line, "l") == 0) state->log_type = (log_type_t)atoi(value);
      else if (strcmp(line, "a") == 0) strncpy(state->bot_pass, value, MAX_PASS - 1);
      else if (strcmp(line, "u") == 0) strncpy(state->user, value, sizeof(state->user) - 1);
      else if (strcmp(line, "g") == 0) strncpy(state->gecos, value, sizeof(state->gecos) - 1);
      else if (strcmp(line, "v") == 0) strncpy(state->vhost, value, sizeof(state->vhost) - 1);
      else if (strcmp(line, "p") == 0) strncpy(state->bot_comm_pass, value, MAX_PASS - 1);
      else if (strcmp(line, "s") == 0) {
          if (state->server_count < MAX_SERVERS) {
            state->server_list[state->server_count++] = strdup(value);
          }
      }
      else if (strcmp(line, "b") == 0) {
          if (state->trusted_bot_count < MAX_TRUSTED_BOTS) {
            state->trusted_bots[state->trusted_bot_count++] = strdup(value);
          }
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

  if (state->target_nick[0] == '\0' || state->user[0] == '\0' || state->gecos[0] == '\0' ||
      state->bot_pass[0] == '\0' || state->mask_count == 0 ||
      state->server_count == 0) {
      log_message(L_INFO, state, "[CFG] Config file missing required fields.\n");
      return false;
  }
  return true;
}

void config_write(const bot_state_t *state, const char *password) {
  if (strlen(password) > MAX_PASS) return;

  // [FIX] Increased buffer to 20x to handle large Base64 Key
  char plaintext_overrides[MAX_BUFFER * 20] = "";
  int offset = 0;
  int remaining = sizeof(plaintext_overrides);
  int written;

  #define SAFE_APPEND(...) do { \
      if (remaining > 1) { \
          written = snprintf(plaintext_overrides + offset, remaining, __VA_ARGS__); \
          if (written > 0 && written < remaining) { \
              offset += written; remaining -= written; \
          } \
      } \
  } while(0)

  if (state->bot_uuid[0]) SAFE_APPEND("uuid:%s\n", state->bot_uuid);
  if (state->hub_key[0])  SAFE_APPEND("hk:%s\n", state->hub_key);
  
  for (int i = 0; i < state->hub_count; i++) {
      SAFE_APPEND("hub:%s\n", state->hub_list[i]);
  }

  SAFE_APPEND("n:%s\n", state->target_nick);
  if (state->log_type != DEFAULT_LOG_LEVEL) SAFE_APPEND("l:%d\n", state->log_type);
  SAFE_APPEND("a:%s\n", state->bot_pass);
  SAFE_APPEND("u:%s\n", state->user);
  SAFE_APPEND("g:%s\n", state->gecos);
  if (state->vhost[0] != '\0') SAFE_APPEND("v:%s\n", state->vhost);
  if (state->bot_comm_pass[0] != '\0') SAFE_APPEND("p:%s\n", state->bot_comm_pass);

  for (int i = 0; i < state->server_count; i++) {
      SAFE_APPEND("s:%s\n", state->server_list[i]);
  }

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
      const char *prefix = c->is_managed ? "hc" : "c";
      if (c->is_managed) {
          if (c->key[0] != '\0') SAFE_APPEND("%s:%s %s|%ld\n", prefix, c->name, c->key, (long)c->timestamp);
          else SAFE_APPEND("%s:%s|%ld\n", prefix, c->name, (long)c->timestamp);
      } else {
          if (c->key[0] != '\0') SAFE_APPEND("%s:%s %s\n", prefix, c->name, c->key);
          else SAFE_APPEND("%s:%s\n", prefix, c->name);
      }
  }

  for (int i = 0; i < state->mask_count; i++) {
      const char *prefix = state->auth_masks[i].is_managed ? "hm" : "m";
      if (state->auth_masks[i].is_managed) {
          SAFE_APPEND("%s:%s|%ld\n", prefix, state->auth_masks[i].mask, (long)state->auth_masks[i].timestamp);
      } else {
          SAFE_APPEND("%s:%s\n", prefix, state->auth_masks[i].mask);
      }
  }

  for (int i = 0; i < state->trusted_bot_count; i++) {
      SAFE_APPEND("b:%s\n", state->trusted_bots[i]);
  }

  for (int i = 0; i < state->op_mask_count; i++) {
      const char *prefix = state->op_masks[i].is_managed ? "ho" : "o";
      if (state->op_masks[i].is_managed) {
          SAFE_APPEND("%s:%s:%s|%ld\n", prefix, state->op_masks[i].mask, state->op_masks[i].password, (long)state->op_masks[i].timestamp);
      } else {
          SAFE_APPEND("%s:%s:%s\n", prefix, state->op_masks[i].mask, state->op_masks[i].password);
      }
  }

  #undef SAFE_APPEND

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
  if (!ciphertext) handle_fatal_error("malloc failed for ciphertext");
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

if (state->hub_authenticated && state->hub_fd != -1) {
        config_notify_hub_if_changed((bot_state_t *)state);
    }

}
