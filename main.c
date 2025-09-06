#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
  state->log_type = L_INFO | L_MSG | L_CTCP | L_CMD;
  state->last_pong_time = time(NULL);
  state->nick_release_time = time(NULL) - NICK_TAKE_TIME;
  state->server_fd = -1;
  state->server_count = 0;
  state->mask_count = 0;
  state->op_mask_count = 0;
}

static void state_destroy(bot_state_t *state) {
  for (int i = 0; i < state->server_count; i++) free(state->server_list[i]);
  for (int i = 0; i < state->mask_count; i++) free(state->auth_masks[i]);
  channel_list_destroy(state);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <config_password>\n", argv[0]);
    return 1;
  }

  ssl_init_openssl();
  printf("%s %s\n", BOT_NAME, BOT_VERSION);
  bot_state_t state;
  state_init(&state);

  strncpy(state.startup_password, argv[1], sizeof(state.startup_password) - 1);
  state.startup_password[sizeof(state.startup_password) - 1] = '\0';
  get_local_ip(&state);

#ifndef DEBUG
#else
  printf("[Entering DEBUG mode]\n");
#endif

  setup_signals();

  config_load(&state, state.startup_password, CONFIG_FILE);
  change_proc_name(argc, argv);

  if (state.server_count == 0 && !state.default_server_ignored) {
    state.server_list[0] = strdup(DEFAULT_SERVER);
    state.server_count = 1;
  }
  if (state.ignored_default_channel[0] == '\0' ||
      strcasecmp(state.ignored_default_channel, DEFAULT_CHANNEL) != 0) {
    channel_add(&state, DEFAULT_CHANNEL);
  }
  if (state.ignored_default_mask[0] == '\0' ||
      strcasecmp(state.ignored_default_mask, DEFAULT_USERMASK) != 0) {
    state.auth_masks[state.mask_count++] = strdup(DEFAULT_USERMASK);
  }

  state.server_list[state.server_count] = NULL;
  state.auth_masks[state.mask_count] = NULL;

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
  printf("-- Clean exit --\n");
  return 0;
}
