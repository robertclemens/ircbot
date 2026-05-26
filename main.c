#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "bot.h"

void ssl_init_openssl(void) {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

static void state_init(bot_state_t *state) {
  memset(state, 0, sizeof(bot_state_t));
  state->status = S_NONE;
  state->log_type = DEFAULT_LOG_LEVEL;
  state->last_pong_time = time(NULL);
  state->nick_release_time = time(NULL) - NICK_TAKE_TIME;
  state->actual_hostname_ts = 0;
  state->current_nick_ts = time(NULL);
  state->server_fd = -1;
  state->server_count = 0;
  state->user_record_count = 0;
  state->mask_record_count = 0;
  state->trusted_bot_count = 0;
  state->config_dirty = false;
  hub_client_init(state);
  srand(time(NULL));
}

static void state_destroy(bot_state_t *state) {
  for (int i = 0; i < state->server_count; i++)
    free(state->server_list[i]);
  for (int i = 0; i < state->hub_count; i++)
    free(state->hub_list[i]);
  channel_list_destroy(state);
  OPENSSL_cleanse(state->hub_key_raw,     sizeof(state->hub_key_raw));
  munlock(state->hub_key_raw,             sizeof(state->hub_key_raw));
  OPENSSL_cleanse(state->startup_password, MAX_PASS);
  munlock(state->startup_password,         MAX_PASS);
}

static void flush_stdin_if_needed(const char *buffer, size_t len) {
  if (strlen(buffer) == len - 1 && strchr(buffer, '\n') == NULL) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
      ;
  }
}

static void get_input(const char *prompt, char *buffer, size_t len) {
  printf("%s: ", prompt);
  fflush(stdout);
  if (fgets(buffer, len, stdin) == NULL) {
    buffer[0] = '\0';
    return;
  }
  flush_stdin_if_needed(buffer, len);
  buffer[strcspn(buffer, "\r\n")] = 0;
}

static void get_password(const char *prompt, char *buffer, size_t len) {
  struct termios oldt, newt;
  printf("%s: ", prompt);
  fflush(stdout);
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  if (fgets(buffer, len, stdin) == NULL) {
    buffer[0] = '\0';
  } else {
    flush_stdin_if_needed(buffer, len);
    buffer[strcspn(buffer, "\r\n")] = 0;
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  printf("\n");
}

static bool get_confirmed_password(const char *prompt, char *buffer,
                                   size_t len) {
  char confirm_buffer[MAX_PASS];
  get_password(prompt, buffer, len);
  get_password("Confirm password", confirm_buffer, sizeof(confirm_buffer));
  if (strcmp(buffer, confirm_buffer) == 0 && strlen(buffer) > 0) {
    printf("Passwords match. Accepted.\n");
    return true;
  } else {
    printf(
        "🚨 ERROR: Passwords do not match or are empty. Please try again.\n");
    memset(buffer, 0, len);
    return false;
  }
}


void daemonize(void) {
  pid_t pid;

  pid = fork();
  if (pid < 0) { perror("fork"); exit(1); }
  if (pid > 0) exit(0);

  if (setsid() < 0) { perror("setsid"); exit(1); }

  pid = fork();
  if (pid < 0) { perror("fork"); exit(1); }
  if (pid > 0) exit(0);

  umask(0027);

  int devnull = open("/dev/null", O_RDWR);
  if (devnull < 0) exit(1);
  dup2(devnull, STDIN_FILENO);
  dup2(devnull, STDOUT_FILENO);
  dup2(devnull, STDERR_FILENO);
  if (devnull > STDERR_FILENO) close(devnull);
}

static void passfile_build_context(char *buf, size_t len) {
  struct stat home_st;
  struct utsname uts;
  struct passwd *pw = getpwuid(getuid());

  memset(&home_st, 0, sizeof(home_st));
  memset(&uts, 0, sizeof(uts));
  if (pw && pw->pw_dir)
    stat(pw->pw_dir, &home_st);
  uname(&uts);

  snprintf(buf, len, "%lu:%lu:%u:%u:%s",
           (unsigned long)home_st.st_ino,
           (unsigned long)home_st.st_dev,
           (unsigned int)getuid(),
           (unsigned int)getgid(),
           uts.machine);
}

static bool passfile_derive_key(const char *ctx, const unsigned char *salt,
                                unsigned char *key) {
  return PKCS5_PBKDF2_HMAC(ctx, (int)strlen(ctx), salt, SALT_SIZE,
                            PBKDF2_ITERATIONS, EVP_sha256(), 32, key) == 1;
}

static bool passfile_create(const char *path, const char *password) {
  unsigned char salt[SALT_SIZE];
  unsigned char key[32];
  unsigned char tag[GCM_TAG_LEN];
  char ctx[256];
  bool ok = false;

  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    fprintf(stderr, "RNG failure.\n");
    goto done;
  }

  passfile_build_context(ctx, sizeof(ctx));
  if (!passfile_derive_key(ctx, salt, key)) {
    fprintf(stderr, "Key derivation failed.\n");
    goto done;
  }

  int pass_len = (int)strlen(password);
  unsigned char *enc_buf = malloc((size_t)(GCM_IV_LEN + pass_len));
  if (!enc_buf) goto done;

  int enc_len = crypto_aes_gcm_encrypt((const unsigned char *)password,
                                       pass_len, key, enc_buf, tag);
  if (enc_len <= 0) {
    fprintf(stderr, "Encryption failed.\n");
    free(enc_buf);
    goto done;
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) { perror("open"); free(enc_buf); goto done; }
  if (fchmod(fd, 0600) != 0) { perror("fchmod"); close(fd); free(enc_buf); goto done; }

  ok = (write(fd, salt,    SALT_SIZE)   == SALT_SIZE &&
        write(fd, enc_buf, enc_len)     == enc_len   &&
        write(fd, tag,     GCM_TAG_LEN) == GCM_TAG_LEN);

  if (!ok) perror("write " PASS_FILE);
  close(fd);
  free(enc_buf);

done:
  memset(key, 0, sizeof(key));
  memset(ctx, 0, sizeof(ctx));
  return ok;
}

static bool passfile_load(const char *path, char *out_pass, size_t out_len) {
  struct stat st;
  bool ok = false;

  if (stat(path, &st) != 0) return false;

  if (st.st_uid != getuid()) {
    fprintf(stderr, "[WARN] %s: wrong owner, ignoring.\n", path);
    return false;
  }
  if ((st.st_mode & 0777) != 0600) {
    fprintf(stderr, "[WARN] %s: must be 0600, ignoring.\n", path);
    return false;
  }

  int min_size = SALT_SIZE + GCM_IV_LEN + 1 + GCM_TAG_LEN;
  if (st.st_size < min_size) return false;

  int fd = open(path, O_RDONLY);
  if (fd < 0) return false;

  size_t total = (size_t)st.st_size;
  unsigned char *buf = malloc(total);
  if (!buf) { close(fd); return false; }

  if (read(fd, buf, total) != (ssize_t)total) {
    close(fd); free(buf); return false;
  }
  close(fd);

  unsigned char *salt    = buf;
  unsigned char *enc_blk = buf + SALT_SIZE;
  int enc_len            = (int)(total - SALT_SIZE - GCM_TAG_LEN);
  unsigned char *tag     = buf + SALT_SIZE + enc_len;

  unsigned char key[32];
  char ctx[256];
  passfile_build_context(ctx, sizeof(ctx));
  if (!passfile_derive_key(ctx, salt, key)) goto done;

  mlock(out_pass, out_len);
  unsigned char *plain = malloc((size_t)enc_len);
  if (!plain) goto done;
  mlock(plain, (size_t)enc_len);

  int dec_len = crypto_aes_gcm_decrypt(enc_blk, enc_len, key, plain, tag);
  if (dec_len > 0 && (size_t)dec_len < out_len) {
    plain[dec_len] = 0;
    memcpy(out_pass, plain, (size_t)dec_len + 1);
    ok = true;
  } else {
    fprintf(stderr, "[WARN] %s: decryption failed (wrong machine or tampered file).\n", path);
  }

  memset(plain, 0, (size_t)enc_len);
  munlock(plain, (size_t)enc_len);
  free(plain);

done:
  memset(key, 0, sizeof(key));
  memset(ctx, 0, sizeof(ctx));
  munlock(out_pass, out_len);
  free(buf);
  return ok;
}

static void run_config_wizard(void) {
  bot_state_t state;
  char config_pass[MAX_PASS];
  char server_buf[MAX_BUFFER];
  char chan_buf[MAX_CHAN];
  char confirm_char[16];
  char admin_name[64];
  char admin_pass[MAX_PASS];
#define WIZARD_MAX_MASKS 20
  char admin_masks[WIZARD_MAX_MASKS][MAX_MASK_LEN];
  int  admin_mask_count = 0;
  memset(admin_name,  0, sizeof(admin_name));
  memset(admin_pass,  0, sizeof(admin_pass));
  memset(admin_masks, 0, sizeof(admin_masks));

  printf("--- IRC Bot Initial Setup ---\n");
  printf("No config file found. Let's create one.\n\n");

  do {
    state_init(&state);
    memset(config_pass, 0, MAX_PASS);
    memset(server_buf, 0, MAX_BUFFER);
    memset(chan_buf, 0, MAX_CHAN);

    printf("==========================================\n");
    printf("         Starting Configuration Wizard      \n");
    printf("==========================================\n");

    printf("\n--- Setup Config Master Password ---\n");
    while (!get_confirmed_password("Enter new config password", config_pass,
                                   MAX_PASS))
      ;

    printf("\n--- Setup Bot Nickname ---\n");
    while (true) {
      get_input("Enter bot nick", state.target_nick, MAX_NICK);
      if (is_valid_bot_nick(state.target_nick)) {
        snprintf(state.current_nick, MAX_NICK, "%s", state.target_nick);
        break;
      }
      if (strchr(state.target_nick, '|'))
        printf("ERROR: Nick cannot contain '|' (reserved as protocol delimiter).\n");
      else
        printf("ERROR: Invalid nick length.\n");
    }

    get_input("Enter bot username (ident)", state.user, sizeof(state.user));
    get_input("Enter bot real name (gecos)", state.gecos, sizeof(state.gecos));
    get_input("Enter VHOST IP (optional, press Enter for default [no vhost])",
              state.vhost, sizeof(state.vhost));

    printf("\n--- Setup First Admin ---\n");
    memset(admin_name,  0, sizeof(admin_name));
    memset(admin_pass,  0, sizeof(admin_pass));
    memset(admin_masks, 0, sizeof(admin_masks));
    admin_mask_count = 0;
    while (true) {
      get_input("Enter admin friendly name (no spaces, e.g. robert)", admin_name, sizeof(admin_name));
      if (strlen(admin_name) > 0 && !strchr(admin_name,' ') && !strchr(admin_name,'|'))
        break;
      printf("ERROR: Name cannot contain spaces or '|'.\n");
    }
    while (!get_confirmed_password("Enter admin password", admin_pass, MAX_PASS))
      ;
    printf("\n--- Setup Admin Usermasks ---\n");
    printf("Enter usermasks for this admin (e.g. nick!*@*.example.com).\n");
    printf("Press Enter with no mask when done (at least one required).\n\n");
    while (admin_mask_count < WIZARD_MAX_MASKS) {
      char tmp_mask[MAX_MASK_LEN] = {0};
      printf("Usermask %d%s: ", admin_mask_count + 1,
             admin_mask_count == 0 ? " (required)" : " (or Enter to finish)");
      fflush(stdout);
      char *res = fgets(tmp_mask, sizeof(tmp_mask), stdin);
      if (!res) break;
      tmp_mask[strcspn(tmp_mask, "\n")] = '\0';
      if (tmp_mask[0] == '\0') {
        if (admin_mask_count == 0) { printf("ERROR: At least one usermask required.\n"); continue; }
        break;
      }
      if (!strchr(tmp_mask, '!') || !strchr(tmp_mask, '@')) {
        printf("ERROR: Mask must contain '!' and '@'. Try again.\n");
        continue;
      }
      snprintf(admin_masks[admin_mask_count], MAX_MASK_LEN, "%s", tmp_mask);
      admin_mask_count++;
    }

    printf("\n--- Setup IRC Server ---\n");
    while (true) {
      get_input("Enter IRC server (e.g., irc.efnet.org)", server_buf,
                MAX_BUFFER);
      if (strlen(server_buf) > 3 && strchr(server_buf, '.'))
        break;
      printf("🚨 ERROR: Invalid server format.\n");
    }

    printf("\n--- Setup Initial Channel ---\n");
    while (true) {
      get_input("Enter channel to join (e.g., #bots) [Optional, Enter to skip]",
                chan_buf, MAX_CHAN);
      if (strlen(chan_buf) == 0)
        break;
      if (chan_buf[0] == '#' && strlen(chan_buf) > 1)
        break;
      printf("🚨 ERROR: Channel must start with '#'.\n");
    }

    // Hub Configuration (Optional)
    printf("\n--- Hub Configuration (Optional) ---\n");
    printf(
        "If you want to connect to an IRC Hub for centralized management,\n");
    printf("you need a UUID and private key generated by the hub admin.\n");
    printf("Press Enter to skip, or enter 'y' to configure hub connection.\n");

    char hub_choice[16];
    get_input("Configure hub connection? (y/N)", hub_choice,
              sizeof(hub_choice));

    if (hub_choice[0] == 'y' || hub_choice[0] == 'Y') {
      char uuid_input[128];
      char privkey_input[4096];
      char hub_addr[256];
      bool uuid_valid = false;
      bool key_valid = false;

      // UUID Validation
      printf("\n--- Hub UUID ---\n");
      printf("Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 characters)\n");

      while (!uuid_valid) {
        get_input("Enter bot UUID from hub admin", uuid_input,
                  sizeof(uuid_input));

        // Validate UUID format
        if (strlen(uuid_input) == 36 && uuid_input[8] == '-' &&
            uuid_input[13] == '-' && uuid_input[18] == '-' &&
            uuid_input[23] == '-') {

          bool all_hex = true;
          for (int i = 0; i < 36; i++) {
            if (i == 8 || i == 13 || i == 18 || i == 23)
              continue; // Skip hyphens
            char c = uuid_input[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) {
              all_hex = false;
              break;
            }
          }

          if (all_hex) {
            uuid_valid = true;
            printf("UUID format validated: %s\n", uuid_input);
          } else {
            printf("🚨 ERROR: UUID contains invalid characters (must be hex "
                   "digits and hyphens).\n");
          }
        } else {
          printf("🚨 ERROR: Invalid UUID format.\n");
          printf("Expected: 8-4-4-4-12 hex digits separated by hyphens\n");
          printf("Example:  918ef266-6755-4dea-adcd-9a64cecdf7a9\n");
        }
      }

      // Private Key Validation
      printf("\n--- Hub Private Key ---\n");
      printf("This should be a Base64-encoded string from hub admin.\n");
      printf(
          "It will look like: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ...\n");
      printf("Length: typically 1600-1800 characters for RSA-2048\n");

      while (!key_valid) {
        printf("\nPaste the Base64 private key (can be multiple lines, end "
               "with blank line):\n");

        privkey_input[0] = '\0';
        char line[1024];
        int total_len = 0;

        while (1) {
          if (fgets(line, sizeof(line), stdin) == NULL)
            break;

          // Remove newline
          line[strcspn(line, "\r\n")] = '\0';

          // Empty line = end of input
          if (strlen(line) == 0)
            break;

          // Append to privkey_input
          int line_len = strlen(line);
          //            if (total_len + line_len < sizeof(privkey_input) - 1) {
          if ((size_t)(total_len + line_len) < sizeof(privkey_input) - 1) {
            memcpy(privkey_input + total_len, line, line_len);
            total_len += line_len;
            privkey_input[total_len] = '\0';
          } else {
            printf("🚨 ERROR: Key too long (max %zu chars).\n",
                   sizeof(privkey_input) - 1);
            privkey_input[0] = '\0';
            total_len = 0;
            break;
          }
        }

        if (total_len == 0) {
          printf("🚨 ERROR: No key entered.\n");
          continue;
        }

        // Validate Base64
        bool is_base64 = true;
        for (int i = 0; i < total_len; i++) {
          char c = privkey_input[i];
          if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
            is_base64 = false;
            printf("🚨 ERROR: Invalid character at position %d: '%c'\n", i, c);
            printf("Base64 only allows: A-Z, a-z, 0-9, +, /, =\n");
            break;
          }
        }

        if (!is_base64) {
          privkey_input[0] = '\0';
          continue;
        }

        // Check reasonable length (RSA-2048 private key in Base64 is ~1700
        // chars)
        if (total_len < 800) {
          printf("🚨 WARNING: Key seems too short (%d chars). RSA-2048 keys "
                 "are typically 1600-1800 chars.\n",
                 total_len);
          char retry[16];
          get_input("Use this key anyway? (y/N)", retry, sizeof(retry));
          if (retry[0] != 'y' && retry[0] != 'Y') {
            privkey_input[0] = '\0';
            continue;
          }
        }

        if (total_len > 3000) {
          printf("🚨 WARNING: Key seems too long (%d chars). RSA-2048 keys are "
                 "typically 1600-1800 chars.\n",
                 total_len);
          char retry[16];
          get_input("Use this key anyway? (y/N)", retry, sizeof(retry));
          if (retry[0] != 'y' && retry[0] != 'Y') {
            privkey_input[0] = '\0';
            continue;
          }
        }

        key_valid = true;
        printf("Private key validated (%d characters).\n", total_len);
      }

      // Hub Address
      printf("\n--- Hub Address ---\n");
      while (true) {
        get_input("Enter hub address (e.g., 127.0.0.1:6000)", hub_addr,
                  sizeof(hub_addr));

        // Basic validation: must have colon and port
        char *colon = strchr(hub_addr, ':');
        if (colon && strlen(colon + 1) > 0) {
          int port = atoi(colon + 1);
          if (port > 0 && port < 65536) {
            printf("Hub address accepted: %s\n", hub_addr);
            break;
          }
        }
        printf(
            "🚨 ERROR: Invalid format. Use: IP:PORT (e.g., 127.0.0.1:6000)\n");
      }

      // Store in state
      snprintf(state.bot_uuid, sizeof(state.bot_uuid), "%s", uuid_input);
      snprintf(state.hub_key, sizeof(state.hub_key), "%s", privkey_input);
      {
        int dec_len = 0;
        unsigned char *dec = base64_decode(privkey_input, &dec_len);
        if (dec && dec_len == HUB_KEY_RAW_LEN) {
          memcpy(state.hub_key_raw, dec, HUB_KEY_RAW_LEN);
          OPENSSL_cleanse(dec, HUB_KEY_RAW_LEN);
        }
        if (dec) free(dec);
      }

      if (state.hub_count < MAX_SERVERS) {
        state.hub_list[state.hub_count++] = strdup(hub_addr);
      }

      printf("\n✓ Hub configuration saved.\n");
    } else {
      printf("Skipping hub configuration.\n");
    }

    printf("\n==========================================\n");
    printf("     Configuration Summary (Review)         \n");
    printf("==========================================\n");
    printf("Bot Nick: %s\n", state.target_nick);
    printf("IRC Server: %s\n", server_buf);
    printf("Managed: %s\n", (state.hub_count > 0 ? "YES" : "NO"));

    get_input("Does this look correct? (Y/n)", confirm_char,
              sizeof(confirm_char));
    if (confirm_char[0] == 'n' || confirm_char[0] == 'N') {
      printf("\nRestarting configuration wizard...\n\n");
      for (int i = 0; i < state.hub_count; i++)
        free(state.hub_list[i]);
      state.hub_count = 0;
    } else {
      break;
    }
  } while (true);

  // Commit — create admin user_record + all collected mask_records
  {
    unsigned char rnd[16];
    RAND_bytes(rnd, sizeof(rnd));
    rnd[6]=(rnd[6]&0x0f)|0x40; rnd[8]=(rnd[8]&0x3f)|0x80;
    char new_uuid[37];
    snprintf(new_uuid, sizeof(new_uuid),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
             rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);
    time_t now = time(NULL);
    user_record_t *u = &state.user_records[state.user_record_count++];
    memset(u, 0, sizeof(*u));
    snprintf(u->uuid,     sizeof(u->uuid),     "%s", new_uuid);
    snprintf(u->name,     sizeof(u->name),     "%s", admin_name);
    snprintf(u->password, sizeof(u->password), "%s", admin_pass);
    u->type = 'a'; u->is_active = true; u->timestamp = now;
    for (int mi = 0; mi < admin_mask_count && state.mask_record_count < MAX_USER_MASKS; mi++) {
      mask_record_t *m = &state.mask_records[state.mask_record_count++];
      memset(m, 0, sizeof(*m));
      snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
      snprintf(m->mask, sizeof(m->mask), "%s", admin_masks[mi]);
      m->is_active = true; m->timestamp = now;
    }
    memset(admin_pass,  0, sizeof(admin_pass));
    memset(admin_masks, 0, sizeof(admin_masks));
  }
#undef WIZARD_MAX_MASKS
  state.server_list[state.server_count++] = strdup(server_buf);

  if (strlen(chan_buf) > 0) {
    chan_t *c = channel_add(&state, chan_buf);
    if (c) {
      c->is_managed = true; // Active by default
      c->timestamp = time(NULL);
      c->status = C_OUT; // Will join on main loop start
    }
  }

  printf("\n--- Finalizing Configuration ---\n");
  config_write(&state, config_pass);
  printf("\nConfiguration saved to %s.\n", CONFIG_FILE);
  printf("You can now start the bot:\n");
  printf("  Run './ircbot -p' to create a machine-bound password file, then './ircbot'\n");
  printf("  Or run './ircbot' directly and enter the password when prompted.\n");
}

int main(int argc, char *argv[]) {
#ifdef HAVE_CURL
  curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

  bool do_setup = false;
  bool do_passfile = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-setup") == 0) do_setup = true;
    if (strcmp(argv[i], "-p")     == 0) do_passfile = true;
  }

  if (do_setup) {
    if (access(CONFIG_FILE, F_OK) == 0) {
      fprintf(stderr, "Error: Config file '%s' already exists.\n", CONFIG_FILE);
      return 1;
    }
    run_config_wizard();
    return 0;
  }

  if (do_passfile) {
    char pass1[MAX_PASS], pass2[MAX_PASS];
    do {
      get_password("Config Password", pass1, sizeof(pass1));
      if (!pass1[0]) {
        fprintf(stderr, "Password cannot be empty.\n");
        return 1;
      }
      get_password("Confirm Config Password", pass2, sizeof(pass2));
      if (strcmp(pass1, pass2) != 0)
        printf("Passwords do not match. Try again.\n");
    } while (strcmp(pass1, pass2) != 0);

    bool ok = passfile_create(PASS_FILE, pass1);
    memset(pass1, 0, sizeof(pass1));
    memset(pass2, 0, sizeof(pass2));
    if (ok) {
      printf("Saved: %s (0600, machine-bound)\n", PASS_FILE);
      return 0;
    }
    fprintf(stderr, "Failed to create %s.\n", PASS_FILE);
    return 1;
  }

  if (access(CONFIG_FILE, F_OK) != 0) {
    fprintf(stderr, "No config file found. First run: ./ircbot -setup\n");
    return 1;
  }

  /* Password resolution: .ircbot.pass → stdin prompt */
  char startup_password[MAX_PASS];
  memset(startup_password, 0, sizeof(startup_password));

  if (!passfile_load(PASS_FILE, startup_password, sizeof(startup_password))) {
    get_password("Config Password", startup_password, sizeof(startup_password));
    if (!startup_password[0]) {
      fprintf(stderr, "No password provided.\n");
      return 1;
    }
  }

  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  daemonize();

  ssl_init_openssl();

  int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0600);
  if (pid_fd == -1) {
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
    /* Read existing PID to report the conflict clearly */
    char existing[16] = "";
    if (read(pid_fd, existing, sizeof(existing) - 1) > 0) {
      existing[strcspn(existing, "\n")] = '\0';
      fprintf(stderr, "Already running (pid %s) — %s\n", existing, PID_FILE);
    } else {
      fprintf(stderr, "Already running — %s locked\n", PID_FILE);
    }
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  /* Truncate then write so no stale bytes remain if new PID is shorter */
  if (ftruncate(pid_fd, 0) < 0) {
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  char pid_str[16];
  snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
  if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
    close(pid_fd);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }

  bot_state_t state;
  state_init(&state);
  state.pid_fd = pid_fd;
  if (!realpath(argv[0], state.executable_path)) {
    close(pid_fd);
    remove(PID_FILE);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  get_local_ip(&state);
  setup_signals();

  if (!config_load(&state, startup_password, CONFIG_FILE)) {
    close(pid_fd);
    remove(PID_FILE);
    memset(startup_password, 0, sizeof(startup_password));
    return 1;
  }
  /* Lock the raw key material into RAM so it cannot be swapped to disk. */
  mlock(state.hub_key_raw, sizeof(state.hub_key_raw));
  /* XOR-protect the password in memory after successful load */
  bot_set_startup_pass(&state, startup_password);
  memset(startup_password, 0, sizeof(startup_password));
  state.server_list[state.server_count] = NULL;

  // --- MAIN LOOP ---
  while (!(state.status & S_DIE) && !g_shutdown_flag) {
    irc_check_status(&state);
    channel_manager_check_joins(&state);

    // --- HUB GATEKEEPER ---
    // Only execute hub logic if we actually have hubs configured
    if (state.hub_count > 0) {
      hub_client_connect(&state);   // Attempts connection if needed
      hub_client_heartbeat(&state); // Sends pings if authenticated
    }

    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    int max_fd = -1;

    // Add IRC socket to select
    if (state.server_fd != -1) {
      FD_SET(state.server_fd, &read_fds);
      if (state.server_fd > max_fd)
        max_fd = state.server_fd;
    }

    // Hub Socket (Only if it's actually active)
    if (state.hub_count > 0 && state.hub_fd != -1) {
      FD_SET(state.hub_fd, &read_fds);
      if (!state.hub_connected) {
        FD_SET(state.hub_fd, &write_fds);
      }
      if (state.hub_fd > max_fd)
        max_fd = state.hub_fd;
    }

    struct timeval tv = {1, 0}; // 1 second timeout
    if (max_fd == -1) {
      select(0, NULL, NULL, NULL, &tv);
      continue;
    }

    int activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &tv);

    if (activity > 0) {
      // Handle IRC Data
      if (state.server_fd != -1 && FD_ISSET(state.server_fd, &read_fds)) {
        irc_handle_read(&state);
      }

      // Handle Hub Async Connection Completion
      if (state.hub_fd != -1 && !state.hub_connected &&
          FD_ISSET(state.hub_fd, &write_fds)) {
        state.hub_connected = true;
        hub_client_on_connect(&state);
      }

      // Handle Hub Incoming Data (Pongs, Configs, etc.)
      if (state.hub_fd != -1 && FD_ISSET(state.hub_fd, &read_fds)) {
        hub_client_process(&state);
      }
    }
  }

  // --- CLEANUP ---
  config_write_with_state_pass(&state);
  irc_disconnect(&state);
  if (state.hub_fd != -1)
    close(state.hub_fd);
  state_destroy(&state);
#ifdef HAVE_CURL
  curl_global_cleanup();
#endif
  close(state.pid_fd);
  remove(PID_FILE);
  return 0;
}
