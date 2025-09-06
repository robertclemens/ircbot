#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "bot.h"

void handle_crypto_errors_silent() { ERR_clear_error(); }

void config_load(bot_state_t *state, const char *password,
                 const char *filename) {
  FILE *in_file = fopen(filename, "rb");
  if (!in_file) {
    return;
  }

  unsigned char salt[SALT_SIZE];
  if (fread(salt, 1, sizeof(salt), in_file) != sizeof(salt)) {
    fclose(in_file);
    return;
  }

  fseek(in_file, 0, SEEK_END);
  long ciphertext_len = ftell(in_file) - SALT_SIZE;
  fseek(in_file, SALT_SIZE, SEEK_SET);
  if (ciphertext_len <= 0) {
    fclose(in_file);
    return;
  }

  unsigned char *ciphertext = malloc(ciphertext_len);
  if (!ciphertext) handle_fatal_error("malloc failed for ciphertext");
  if (fread(ciphertext, 1, ciphertext_len, in_file) != (size_t)ciphertext_len) {
    log_message(
        L_INFO, state,
        "[CFG] Error: Could not read the full contents of the config file.\n");
    fclose(in_file);
    free(ciphertext);
    return;
  }
  fclose(in_file);

  unsigned char key[32], iv[16];
  if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                     (unsigned char *)password, strlen(password), 1, key,
                     iv) == 0) {
    handle_crypto_errors_silent();
    free(ciphertext);
    return;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  unsigned char *plaintext = malloc(ciphertext_len + 1);
  if (!plaintext) handle_fatal_error("malloc failed for plaintext");
  int len;
  int plaintext_len;

  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    log_message(L_INFO, state,
                "[CFG] Decryption failed. Incorrect password?\n");
    free(ciphertext);
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);
    return;
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    log_message(
        L_INFO, state,
        "[CFG] Decryption failed (padding check). Incorrect password?\n");
    free(ciphertext);
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);
    return;
  }
  plaintext_len += len;
  plaintext[plaintext_len] = '\0';

  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);

  char *saveptr1;
  char *line = strtok_r((char *)plaintext, "\n", &saveptr1);

  while (line) {
    if (strlen(line) < 2 || line[0] == '#') {
      line = strtok_r(NULL, "\n", &saveptr1);
      continue;
    }

    if (strncmp(line, "is:true", 7) == 0) {
      state->default_server_ignored = true;
      line = strtok_r(NULL, "\n", &saveptr1);
      continue;
    }
    if (strncmp(line, "im:", 3) == 0) {
      strncpy(state->ignored_default_mask, line + 3, MAX_MASK_LEN - 1);
      line = strtok_r(NULL, "\n", &saveptr1);
      continue;
    }

    char *value = strchr(line, ':');
    if (!value) {
      line = strtok_r(NULL, "\n", &saveptr1);
      continue;
    }
    *value++ = '\0';
    char type = line[0];

    switch (type) {
      case '1':
        strncpy(state->target_nick, value, MAX_NICK - 1);
        break;
      case '3': {
        char *saveptr2;
        char *chan_name = strtok_r(value, " ", &saveptr2);
        char *chan_key = strtok_r(NULL, " ", &saveptr2);
        if (chan_name) {
          chan_t *c = channel_add(state, chan_name);
          if (c && chan_key) strncpy(c->key, chan_key, MAX_KEY - 1);
        }
        break;
      }
      case '4':
        state->log_type = (log_type_t)atoi(value);
        break;
      case '5':
        strncpy(state->bot_pass, value, MAX_PASS - 1);
        break;
      case 's':
        if (state->server_count < MAX_SERVERS) {
          state->server_list[state->server_count++] = strdup(value);
        }
        break;
      case 'm':
        if (state->mask_count < MAX_MASKS) {
          state->auth_masks[state->mask_count++] = strdup(value);
        }
        break;
      case 'i':
        strncpy(state->ignored_default_channel, value, MAX_CHAN - 1);
        break;
      case 'o':
        if (state->op_mask_count < MAX_OP_MASKS) {
          char *saveptr_o;
          char *mask = strtok_r(value, ":", &saveptr_o);
          char *pass = strtok_r(NULL, ":", &saveptr_o);
          if (mask && pass) {
            strncpy(state->op_masks[state->op_mask_count].mask, mask,
                    MAX_MASK_LEN - 1);
            strncpy(state->op_masks[state->op_mask_count].password, pass,
                    MAX_PASS - 1);
            state->op_mask_count++;
          }
        }
        break;
    }
    line = strtok_r(NULL, "\n", &saveptr1);
  }
  free(plaintext);
}

void config_write(const bot_state_t *state, const char *password) {
  if (strlen(password) > MAX_PASS) {
    return;
  }

  char plaintext_overrides[MAX_BUFFER * 4] = "";
  int offset = 0;
  int remaining = sizeof(plaintext_overrides);
  int written;

  if (strcmp(state->target_nick, DEFAULT_NICK) != 0) {
    written = snprintf(plaintext_overrides + offset, remaining, "1:%s\n",
                       state->target_nick);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  if (state->log_type != (L_INFO | L_MSG | L_CTCP | L_CMD)) {
    written = snprintf(plaintext_overrides + offset, remaining, "4:%d\n",
                       state->log_type);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  if (strcmp(state->bot_pass, DEFAULT_BOT_PASS) != 0) {
    written = snprintf(plaintext_overrides + offset, remaining, "5:%s\n",
                       state->bot_pass);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  for (int i = 0; i < state->server_count; i++) {
    if (strcmp(state->server_list[i], DEFAULT_SERVER) != 0 && remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "s:%s\n",
                         state->server_list[i]);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (strcasecmp(c->name, DEFAULT_CHANNEL) != 0 && remaining > 1) {
      if (c->key[0] != '\0') {
        written = snprintf(plaintext_overrides + offset, remaining, "3:%s %s\n",
                           c->name, c->key);
      } else {
        written = snprintf(plaintext_overrides + offset, remaining, "3:%s\n",
                           c->name);
      }
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }
  for (int i = 0; i < state->mask_count; i++) {
    if (strcasecmp(state->auth_masks[i], DEFAULT_USERMASK) != 0 &&
        remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "m:%s\n",
                         state->auth_masks[i]);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }
  if (state->ignored_default_channel[0] != '\0' && remaining > 1) {
    written = snprintf(plaintext_overrides + offset, remaining, "i:%s\n",
                       state->ignored_default_channel);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  if (state->ignored_default_mask[0] != '\0' && remaining > 1) {
    written = snprintf(plaintext_overrides + offset, remaining, "im:%s\n",
                       state->ignored_default_mask);
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  if (state->default_server_ignored && remaining > 1) {
    written = snprintf(plaintext_overrides + offset, remaining, "is:true\n");
    if (written > 0 && written < remaining) {
      offset += written;
      remaining -= written;
    }
  }
  for (int i = 0; i < state->op_mask_count; i++) {
    if (remaining > 1) {
      written = snprintf(plaintext_overrides + offset, remaining, "o:%s:%s\n",
                         state->op_masks[i].mask, state->op_masks[i].password);
      if (written > 0 && written < remaining) {
        offset += written;
        remaining -= written;
      }
    }
  }

  if (strlen(plaintext_overrides) == 0) {
    remove(CONFIG_FILE);
    return;
  }

  unsigned char salt[SALT_SIZE];
  RAND_bytes(salt, sizeof(salt));
  unsigned char key[32], iv[16];
  if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                     (unsigned char *)password, strlen(password), 1, key,
                     iv) == 0) {
    return;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  int plaintext_len = strlen(plaintext_overrides);
  int out_len = plaintext_len + 16;
  unsigned char *out_buf = malloc(out_len);
  if (!out_buf) handle_fatal_error("malloc failed for out_buf");
  int len;
  int ciphertext_len;

  EVP_EncryptUpdate(ctx, out_buf, &len, (unsigned char *)plaintext_overrides,
                    plaintext_len);
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, out_buf + len, &len);
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  FILE *out_file = fopen(CONFIG_FILE, "wb");
  if (!out_file) {
    perror("[CFG] Failed to open .ircbot for writing");
    free(out_buf);
    return;
  }

  fwrite(salt, 1, sizeof(salt), out_file);
  fwrite(out_buf, 1, ciphertext_len, out_file);

  fclose(out_file);
  free(out_buf);
  chmod(CONFIG_FILE, S_IRUSR | S_IWUSR);
}
