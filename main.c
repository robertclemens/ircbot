#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/select.h>
#include <unistd.h>

#include "bot.h"

void ssl_init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

static void state_init(bot_state_t *state) {
  memset(state, 0, sizeof(bot_state_t));
  state->status = S_NONE;
  strncpy(state->target_nick, DEFAULT_NICK, MAX_NICK - 1);
  strncpy(state->bot_pass, DEFAULT_BOT_PASS, MAX_PASS - 1);
  state->log_type = 0;
  state->last_pong_time = time(NULL);
  state->nick_release_time = time(NULL) - NICK_TAKE_TIME;
  state->server_fd = -1;
  state->server_count = 0;
  state->mask_count = 0;
  state->op_mask_count = 0;
  state->trusted_bot_count = 0;
}

static void state_destroy(bot_state_t *state) {
  for (int i = 0; i < state->server_count; i++) free(state->server_list[i]);
  for (int i = 0; i < state->mask_count; i++) free(state->auth_masks[i]);
  for (int i = 0; i < state->trusted_bot_count; i++)
    free(state->trusted_bots[i]);
  channel_list_destroy(state);
}

int main(void) {
  int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0666);
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

  char *startup_password = getenv(CONFIG_PASS_ENV_VAR);
  if (!startup_password) {
    fprintf(stderr, "Error: %s environment variable not set.\n",
            CONFIG_PASS_ENV_VAR);
    return 1;
  }

  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  bot_state_t state;
  state_init(&state);

  strncpy(state.startup_password, startup_password,
          sizeof(state.startup_password) - 1);
  state.startup_password[sizeof(state.startup_password) - 1] = '\0';

  get_local_ip(&state);

#ifndef DEBUG
#else
  printf("[Entering DEBUG mode]\n");
#endif

  setup_signals();

  channel_add(&state, DEFAULT_CHANNEL);

  config_load(&state, state.startup_password, CONFIG_FILE);

  if (state.server_count == 0 && !state.default_server_ignored) {
    state.server_list[0] = strdup(DEFAULT_SERVER);
    state.server_count = 1;
  }

  if (channel_find(&state, DEFAULT_CHANNEL) == NULL) {
    channel_add(&state, DEFAULT_CHANNEL);
  }

  if (state.ignored_default_channel[0] != '\0' &&
      strcasecmp(state.ignored_default_channel, DEFAULT_CHANNEL) == 0) {
    channel_remove(&state, DEFAULT_CHANNEL);
  }
  if (state.ignored_default_mask[0] == '\0' ||
      strcasecmp(state.ignored_default_mask, DEFAULT_USERMASK) != 0) {
    state.auth_masks[state.mask_count++] = strdup(DEFAULT_USERMASK);
  }

  state.server_list[state.server_count] = NULL;
  state.auth_masks[state.mask_count] = NULL;
  state.trusted_bots[state.trusted_bot_count] = NULL;

  while (!(state.status & S_DIE)) {
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
  printf("Bot shutting down...\n");
  config_write(&state, state.startup_password);
  irc_disconnect(&state);
  state_destroy(&state);
  remove(PID_FILE);
  printf("-- Clean exit --\n");
  return 0;
}
