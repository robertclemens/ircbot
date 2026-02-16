#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>


#include "bot.h"

void ssl_init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

static void state_init(bot_state_t *state) {
  memset(state, 0, sizeof(bot_state_t));
  state->status = S_NONE;
  state->log_type = DEFAULT_LOG_LEVEL;
  state->last_pong_time = time(NULL);
  state->nick_release_time = time(NULL) - NICK_TAKE_TIME;
  state->server_fd = -1;
  state->server_count = 0;
  state->mask_count = 0;
  state->op_mask_count = 0;
  state->trusted_bot_count = 0;
  hub_client_init(state);
  srand(time(NULL));
}

static void state_destroy(bot_state_t *state) {
  for (int i = 0; i < state->server_count; i++)
    free(state->server_list[i]);
  for (int i = 0; i < state->hub_count; i++)
    free(state->hub_list[i]);
  channel_list_destroy(state);
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

// [NEW] Helper to read file content safely and strip newlines for config
// compatibility
// static bool read_key_from_file(const char *filepath, char *dest, size_t
// max_len) {
//    FILE *f = fopen(filepath, "r");
//    if (!f) return false;
//
// Read the file
//    size_t n = fread(dest, 1, max_len - 1, f);
//    dest[n] = 0;
//    fclose(f);
//
//    if (n == 0) return false;

// Strip newlines to create a single long string (Base64 Safe)
// char *src = dest;
// char *dst = dest;
// while (*src) {
//    if (*src != '\r' && *src != '\n') {
//        *dst++ = *src;
//    }
//    src++;
//}
// *dst = 0;
//
// Basic validation: Check for PEM header OR Base64 start char
// 'L' is the Base64 char for the start of "-----"
//    if (strstr(dest, "-----BEGIN") == NULL && strncmp(dest, "LS0t", 4) != 0) {
//        printf("🚨 Warning: File does not appear to contain a PEM key or
//        Base64-encoded PEM.\n"); return false;
//    }
//    return true;
//}

static void run_config_wizard(void) {
  bot_state_t state;
  char config_pass[MAX_PASS];
  char mask_buf[MAX_MASK_LEN];
  char server_buf[MAX_BUFFER];
  char chan_buf[MAX_CHAN];
  char confirm_char[16];

  printf("--- IRC Bot Initial Setup ---\n");
  printf("No config file found. Let's create one.\n\n");

  do {
    state_init(&state);
    memset(config_pass, 0, MAX_PASS);
    memset(mask_buf, 0, MAX_MASK_LEN);
    memset(server_buf, 0, MAX_BUFFER);
    memset(chan_buf, 0, MAX_CHAN);

    printf("==========================================\n");
    printf("         Starting Configuration Wizard      \n");
    printf("==========================================\n");

    printf("\n--- Setup Config Master Password ---\n");
    while (!get_confirmed_password(
        "Enter new config password (for BOT_PASS env var)", config_pass,
        MAX_PASS))
      ;

    printf("\n--- Setup Bot Nickname ---\n");
    while (true) {
      get_input("Enter bot nick", state.target_nick, MAX_NICK);
      if (strlen(state.target_nick) > 0 &&
          strlen(state.target_nick) < MAX_NICK) {
        strncpy(state.current_nick, state.target_nick, MAX_NICK - 1);
        state.current_nick[MAX_NICK - 1] = '\0';
        break;
      }
      printf("🚨 ERROR: Invalid nick length.\n");
    }

    get_input("Enter bot username (ident)", state.user, sizeof(state.user));
    get_input("Enter bot real name (gecos)", state.gecos, sizeof(state.gecos));
    get_input("Enter VHOST IP (optional, press Enter for default [no vhost])",
              state.vhost, sizeof(state.vhost));

    printf("\n--- Setup Admin Password ---\n");
    while (!get_confirmed_password("Enter new bot ADMIN password",
                                   state.bot_pass, MAX_PASS))
      ;

    printf("\n--- Setup Admin Usermask ---\n");
    while (true) {
      get_input("Enter your admin usermask (e.g., *!*@your.host)", mask_buf,
                MAX_MASK_LEN);
      if (strchr(mask_buf, '!') && strchr(mask_buf, '@') &&
          strlen(mask_buf) > 5)
        break;
      printf("🚨 ERROR: Invalid usermask.\n");
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
            strcat(privkey_input, line);
            total_len += line_len;
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
      strncpy(state.bot_uuid, uuid_input, sizeof(state.bot_uuid) - 1);
      state.bot_uuid[sizeof(state.bot_uuid) - 1] = '\0';

      strncpy(state.hub_key, privkey_input, sizeof(state.hub_key) - 1);
      state.hub_key[sizeof(state.hub_key) - 1] = '\0';

      if (state.hub_count < 10) {
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

  // Commit
  snprintf(state.auth_masks[state.mask_count].mask, MAX_MASK_LEN, "%s",
           mask_buf);
  state.auth_masks[state.mask_count].is_managed = true; // Active by default
  state.auth_masks[state.mask_count].timestamp = time(NULL);
  state.mask_count++;
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
  printf("You can now start the bot using:\n");
  printf("**%s=\"<your_password>\" ./ircbot**\n", CONFIG_PASS_ENV_VAR);
}

int main(int argc, char *argv[]) {
#ifdef HAVE_CURL
  curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
  if (argc > 1 && strcmp(argv[1], "-setup") == 0) {
    if (access(CONFIG_FILE, F_OK) == 0) {
      fprintf(stderr, "Error: Config file '%s' already exists.\n", CONFIG_FILE);
      return 1;
    }
    run_config_wizard();
    return 0;
  }

  int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0600);
  if (pid_fd == -1)
    return 1;
  if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
    close(pid_fd);
    return 1;
  }
  char pid_str[16];
  sprintf(pid_str, "%d\n", getpid());
  if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
  };

  ssl_init_openssl();
  const char *startup_password = getenv(CONFIG_PASS_ENV_VAR);
  if (!startup_password)
    return 1;

  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  bot_state_t state;
  state_init(&state);
  state.pid_fd = pid_fd;
  if (!realpath(argv[0], state.executable_path))
    return 1;
  strncpy(state.startup_password, startup_password,
          sizeof(state.startup_password) - 1);
  get_local_ip(&state);
  setup_signals();

  if (!config_load(&state, state.startup_password, CONFIG_FILE)) {
    remove(PID_FILE);
    return 1;
  }
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
      struct timeval tv_wait = {0, 100000}; // 100ms
      select(0, NULL, NULL, NULL, &tv_wait);
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
        // Note: hub_client_on_connect is likely defined in hub_client.c
        extern void hub_client_on_connect(bot_state_t * state);
        hub_client_on_connect(&state);
      }

      // Handle Hub Incoming Data (Pongs, Configs, etc.)
      if (state.hub_fd != -1 && FD_ISSET(state.hub_fd, &read_fds)) {
        hub_client_process(&state);
      }
    }
  }

  // --- CLEANUP ---
  config_write(&state, state.startup_password);
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
