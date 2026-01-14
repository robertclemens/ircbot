#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/select.h>
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
  srand(time(NULL));
}

static void state_destroy(bot_state_t *state) {
  for (int i = 0; i < state->server_count; i++) free(state->server_list[i]);
  for (int i = 0; i < state->mask_count; i++) free(state->auth_masks[i]);
  channel_list_destroy(state);
}

static void flush_stdin_if_needed(const char *buffer, size_t len) {
  if (strlen(buffer) == len - 1 && strchr(buffer, '\n') == NULL) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
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
    printf("🚨 ERROR: Passwords do not match or are empty. Please try again.\n");
    memset(buffer, 0, len);
    return false;
  }
}

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
              MAX_PASS));

    printf("\n--- Setup Bot Nickname ---\n");
    while (true) {
      printf("Max allowed characters: %d\n", MAX_NICK - 1);
      get_input("Enter bot nick", state.target_nick, MAX_NICK);

      if (strlen(state.target_nick) > 0 &&
          strlen(state.target_nick) < MAX_NICK) {
        strncpy(state.current_nick, state.target_nick, MAX_NICK - 1);
        state.current_nick[MAX_NICK - 1] = '\0';
        printf("Nick accepted: %s\n", state.target_nick);
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
                                   state.bot_pass, MAX_PASS));

    printf("\n--- Setup Admin Usermask ---\n");
    while (true) {
      get_input("Enter your admin usermask (e.g., *!*@your.host)", mask_buf,
                MAX_MASK_LEN);
      if (strchr(mask_buf, '!') && strchr(mask_buf, '@') &&
          strlen(mask_buf) > 5) {
        printf("Usermask accepted: %s\n", mask_buf);
        break;
      }
      printf("🚨 ERROR: Invalid usermask. Must include '!' and '@' (e.g., *!*@host).\n");
    }

    printf("\n--- Setup IRC Server ---\n");
    while (true) {
      get_input("Enter IRC server (e.g., irc.efnet.org)", server_buf,
                MAX_BUFFER);
      if (strlen(server_buf) > 3 && strchr(server_buf, '.')) {
        printf("Server accepted: %s\n", server_buf);
        break;
      }
      printf("🚨 ERROR: Invalid server format.\n");
    }

    printf("\n--- Setup Initial Channel ---\n");
    while (true) {
      get_input("Enter channel to join (e.g., #bots)", chan_buf, MAX_CHAN);
      if (chan_buf[0] == '#' && strlen(chan_buf) > 1) {
        printf("Channel accepted: %s\n", chan_buf);
        break;
      }
      printf("🚨 ERROR: Channel must start with '#'.\n");
    }

    printf("\n==========================================\n");
    printf("     Configuration Summary (Review)         \n");
    printf("==========================================\n");
    printf("Bot Nick:                   %s\n", state.target_nick);
    printf("Bot Ident:                  %s\n", state.user);
    printf("Bot GECOS (Real Name):      %s\n", state.gecos);
    printf("Admin Usermask:             %s\n", mask_buf);
    printf("IRC Server:                 %s\n", server_buf);
    printf("Initial Channel:            %s\n", chan_buf);
    printf("Admin Password:             %s\n", state.bot_pass);
    printf("Config Password:            %s\n", config_pass);
    printf("Vhost:                      %s\n", state.vhost);
    printf("------------------------------------------\n");

    get_input("Does this configuration look correct? (Y/n)", confirm_char,
              sizeof(confirm_char));

    if (confirm_char[0] == 'n' || confirm_char[0] == 'N') {
      printf("\nRestarting configuration wizard...\n\n");
      state_destroy(&state);
    } else {
      break;
    }

  } while (true);

  state.auth_masks[state.mask_count++] = strdup(mask_buf);
  state.server_list[state.server_count++] = strdup(server_buf);
  channel_add(&state, chan_buf);

  printf("\n--- Finalizing Configuration ---\n");
  config_write(&state, config_pass);
  printf("\nConfiguration saved to %s.\n", CONFIG_FILE);
  printf("You can now start the bot using:\n");
  printf("**%s=\"%s\" ./ircbot**\n", CONFIG_PASS_ENV_VAR, config_pass);
}

int main(int argc, char *argv[]) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  if (argc > 1 && strcmp(argv[1], "-c") == 0) {
    if (access(CONFIG_FILE, F_OK) == 0) {
      fprintf(stderr,
              "Error: Config file '%s' already exists. Remove it first to run "
              "setup.\n",
              CONFIG_FILE);
      return 1;
    }
    run_config_wizard();
    return 0;
  }

  int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0600);
  if (pid_fd == -1) {
    perror("Failed to open PID file");
    return 1;
  }

  if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
    if (errno == EWOULDBLOCK) {
      fprintf(stderr,
              "Error: Another instance of the bot is already running.\n");
    } else {
      perror("Failed to lock PID file");
    }
    close(pid_fd);
    return 1;
  }

  char pid_str[16];
  sprintf(pid_str, "%d\n", getpid());
  ssize_t bytes_written = write(pid_fd, pid_str, strlen(pid_str));
  (void)bytes_written;

  ssl_init_openssl();

  const char *startup_password = getenv(CONFIG_PASS_ENV_VAR);
  if (!startup_password) {
    fprintf(stderr, "Error: %s environment variable not set.\n",
            CONFIG_PASS_ENV_VAR);
    return 1;
  }

  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  bot_state_t state;
  state_init(&state);

  state.pid_fd = pid_fd;

  if (realpath(argv[0], state.executable_path) == NULL) {
    fprintf(stderr, "Error: Could not find real path of executable: %s\n",
            strerror(errno));
    return 1;
  }

  strncpy(state.startup_password, startup_password,
          sizeof(state.startup_password) - 1);
  state.startup_password[sizeof(state.startup_password) - 1] = '\0';

  get_local_ip(&state);

#ifndef DEBUG
#else
  printf("[Entering DEBUG mode]\n");
#endif

  setup_signals();
  if (!config_load(&state, state.startup_password, CONFIG_FILE)) {
    fprintf(stderr, "Error: Config file missing or incomplete.\n");
    fprintf(stderr, "Run with -c to create a new one.\n");
    remove(PID_FILE);
    return 1;
  }

  state.server_list[state.server_count] = NULL;
  state.auth_masks[state.mask_count] = NULL;

  while (!(state.status & S_DIE) && !g_shutdown_flag) {
    irc_check_status(&state);
    channel_manager_check_joins(&state);
    if (state.server_fd == -1 && !(state.status & S_DIE)) {
      sleep(5);
      continue;
    }
    fd_set read_fds;
    FD_ZERO(&read_fds);
    if (state.server_fd != -1) {
      FD_SET(state.server_fd, &read_fds);
    }
    int max_fd = state.server_fd;
    struct timeval tv = {1, 0};
    int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
    if (activity < 0) {
      if (errno == EINTR) continue;
      perror("select() error");
      state.status |= S_DIE;
      continue;
    }
    if (activity > 0) {
      if (state.server_fd != -1 && FD_ISSET(state.server_fd, &read_fds)) {
        irc_handle_read(&state);
      }
    }
  }
  config_write(&state, state.startup_password);
  irc_disconnect(&state);
  state_destroy(&state);
  curl_global_cleanup();
  close(state.pid_fd);
  remove(PID_FILE);
  return 0;
}
