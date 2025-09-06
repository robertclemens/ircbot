#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "bot.h"

void irc_disconnect(bot_state_t *state) {
  if (state->is_ssl && state->ssl) {
    SSL_shutdown(state->ssl);
    SSL_free(state->ssl);
    state->ssl = NULL;
  }
  if (state->ssl_ctx) {
    SSL_CTX_free(state->ssl_ctx);
    state->ssl_ctx = NULL;
  }
  if (state->server_fd != -1) {
    close(state->server_fd);
    state->server_fd = -1;
  }
  state->status = S_NONE;
  state->is_ssl = false;
  channel_list_reset_status(state);
}

int irc_printf(bot_state_t *state, const char *format, ...) {
  if (!(state->status & S_CONNECTED)) return -1;
  char buffer[MAX_BUFFER];
  va_list args;
  va_start(args, format);
  int len = vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  if (len < 0) return -1;
  log_message(L_RAW, state, "[RAW_SEND] %s", buffer);
  ssize_t sent;
  if (state->is_ssl) {
    sent = SSL_write(state->ssl, buffer, len);
  } else {
    sent = write(state->server_fd, buffer, len);
  }
  if (sent <= 0) {
    if (state->is_ssl) ERR_print_errors_fp(stderr);
    log_message(L_INFO, state,
                "[INFO] Lost connection to server (write error).\n");
    irc_disconnect(state);
    return -1;
  }
  return sent;
}

void irc_connect(bot_state_t *state) {
  if (state->server_fd != -1) return;
  if (state->server_list[state->current_server_index] == NULL)
    state->current_server_index = 0;

  char server_str[256];
  strncpy(server_str, state->server_list[state->current_server_index],
          sizeof(server_str) - 1);
  server_str[sizeof(server_str) - 1] = '\0';

  char *port_from_config = strrchr(server_str, ':');
  char *host = server_str;
  if (port_from_config) {
    *port_from_config = '\0';
    port_from_config++;
  }

  const char *ports_to_try[] = {"6697", "6667", NULL};
  if (port_from_config) {
    ports_to_try[0] = port_from_config;
  }

  int sockfd = -1;
  for (int i = 0; ports_to_try[i] != NULL && sockfd == -1; i++) {
    log_message(L_INFO, state, "[INFO] Attempting to connect to %s:%s...\n",
                host, ports_to_try[i]);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, ports_to_try[i], &hints, &res) != 0) continue;

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
      if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        continue;
      if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
        if (i == 0) {
          state->ssl_ctx = SSL_CTX_new(TLS_client_method());
          if (!state->ssl_ctx) {
            close(sockfd);
            sockfd = -1;
            continue;
          }
          state->ssl = SSL_new(state->ssl_ctx);
          SSL_set_fd(state->ssl, sockfd);
          if (SSL_connect(state->ssl) == 1) {
            state->is_ssl = true;
            log_message(L_INFO, state,
                        "[INFO] Secure TLS connection established.\n");
          } else {
            log_message(L_INFO, state,
                        "[INFO] SSL handshake failed. Trying insecure.\n");
            SSL_free(state->ssl);
            state->ssl = NULL;
            SSL_CTX_free(state->ssl_ctx);
            state->ssl_ctx = NULL;
            close(sockfd);
            sockfd = -1;
          }
        } else {
          state->is_ssl = false;
          log_message(L_INFO, state,
                      "[INFO] Insecure connection established.\n");
        }
        break;
      }
      close(sockfd);
      sockfd = -1;
    }
    freeaddrinfo(res);
  }

  if (sockfd != -1) {
    state->server_fd = sockfd;
    state->status = S_CONNECTED;
    state->last_pong_time = time(NULL);
    state->connection_time = time(NULL);
    strncpy(state->current_nick, state->target_nick, MAX_NICK - 1);
    state->current_nick[MAX_NICK - 1] = '\0';
    irc_printf(state, "NICK %s\r\n", state->current_nick);
    irc_printf(state, "USER %s 0 * :%s\r\n", DEFAULT_USER, GECOS);
  }
  state->current_server_index++;
}

void irc_handle_read(bot_state_t *state) {
  static char read_buffer[MAX_BUFFER * 2];
  static int buffer_len = 0;
  ssize_t bytes_read;
  if (state->is_ssl) {
    bytes_read = SSL_read(state->ssl, read_buffer + buffer_len,
                          sizeof(read_buffer) - buffer_len - 1);
  } else {
    bytes_read = read(state->server_fd, read_buffer + buffer_len,
                      sizeof(read_buffer) - buffer_len - 1);
  }
  if (bytes_read <= 0) {
    if (state->is_ssl &&
        SSL_get_error(state->ssl, bytes_read) != SSL_ERROR_ZERO_RETURN) {
      ERR_print_errors_fp(stderr);
    }
    irc_disconnect(state);
    buffer_len = 0;
    return;
  }
  buffer_len += bytes_read;
  read_buffer[buffer_len] = '\0';
  char *line_end;
  while ((line_end = strstr(read_buffer, "\r\n")) != NULL) {
    *line_end = '\0';
    log_message(L_RAW, state, "[RAW_RECV] %s\n", read_buffer);
    parser_handle_line(state, read_buffer);
    memmove(read_buffer, line_end + 2, strlen(line_end + 2) + 1);
    buffer_len = strlen(read_buffer);
  }
}

void irc_check_status(bot_state_t *state) {
  if (!(state->status & S_CONNECTED)) {
    irc_connect(state);
    return;
  }
  time_t now = time(NULL);
  if (now - state->last_pong_time > DEAD_SERVER_TIMEOUT) {
    log_message(L_INFO, state, "[INFO] Server timed out. Disconnecting.\n");
    irc_disconnect(state);
    return;
  }
  if (!state->pong_pending &&
      (now - state->last_pong_time > CHECK_LAG_TIMEOUT)) {
    irc_printf(state, "PING :%ld\r\n", now);
    state->pong_pending = true;
  }
  if (state->status & S_AUTHED) {
    channel_manager_check_joins(state);
    if (!state->nick_change_pending) {
      if (strcasecmp(state->current_nick, state->target_nick) != 0) {
        if (now - state->nick_release_time > NICK_TAKE_TIME) {
          if (now - state->last_nick_attempt > NICK_RETRY_TIME) {
            log_message(L_INFO, state,
                        "[INFO] Attempting to reclaim primary nick '%s'.\n",
                        state->target_nick);
            irc_attempt_nick_change(state, state->target_nick);
          }
        } else {
          log_message(L_INFO, state,
                      "[INFO] Nick reclaim on hold. %ld seconds remaining.\n",
                      NICK_TAKE_TIME - (now - state->nick_release_time));
        }
      }
    } else {
      if (state->nick_change_pending) {
        log_message(L_INFO, state,
                    "[INFO] Nick reclaim skipped: nick change pending.\n");
      } else {
        log_message(
            L_INFO, state,
            "[INFO] Nick reclaim skipped: bot not authenticated yet.\n");
      }
    }
  }
}

void irc_attempt_nick_change(bot_state_t *state, const char *new_nick) {
  log_message(L_DEBUG, state, "[DEBUG] Attemping NICK to %s\n", new_nick);
  irc_printf(state, "NICK %s\r\n", new_nick);
  state->last_nick_attempt = time(NULL);
}

void irc_generate_new_nick(bot_state_t *state) {
  const char nick_append_chars[] = "_|`^";
  const int num_special_chars = sizeof(nick_append_chars) - 1;
  char new_nick[MAX_NICK];
  int attempt = state->nick_generation_attempt;

  char base_nick[9];
  strncpy(base_nick, state->target_nick, 8);
  base_nick[8] = '\0';

  if (attempt < num_special_chars) {
    snprintf(new_nick, MAX_NICK, "%s%c", base_nick, nick_append_chars[attempt]);
  } else {
    int numeric_attempt = attempt - num_special_chars;
    if (numeric_attempt < 10) {
      snprintf(new_nick, MAX_NICK, "%s%d", base_nick, numeric_attempt);
    } else {
      state->nick_generation_attempt = 0;
      return;
    }
  }
  strncpy(state->current_nick, new_nick, MAX_NICK - 1);
  state->current_nick[MAX_NICK - 1] = '\0';
  state->nick_generation_attempt++;
  irc_attempt_nick_change(state, new_nick);
}
